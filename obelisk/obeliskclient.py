import logging
from datetime import datetime, timedelta, timezone
from enum import Enum

import requests
from requests.auth import HTTPBasicAuth

import backoff

logger = logging.getLogger(__name__)


class ObeliskError(Exception):
    pass

class ObeliskDateTimeTypeError(Exception):
    pass

class ObeliskPrecisions(Enum):
    MILLISECONDS = 1
    MICROSECONDS = 2
    SECONDS = 3


obelisk_precisions = {
    ObeliskPrecisions.MILLISECONDS: 'milliseconds',
    ObeliskPrecisions.MICROSECONDS: 'microseconds',
    ObeliskPrecisions.SECONDS: 'seconds',
}


retry_timeout = backoff.on_exception(
    wait_gen=backoff.expo,
    exception=(
        ObeliskError,
    ),
    max_tries=3,
)


class Obelisk:
    def __init__(self, base_url, client_id, client_secret, scope_id, version='v2', precision=ObeliskPrecisions.MICROSECONDS):
        self._base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope_id = scope_id
        self._version = version
        self._precision = precision
        self._rpt_token = self.__request_rpt_token()
        self._rpt_refresh_token = None
        self._rpt_refresh_token_expire_date = None

    @retry_timeout
    def __request_access_token(self):
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            body = 'grant_type=client_credentials'
            r = requests.post("{}/auth/realms/idlab-iot/protocol/openid-connect/token".format(self._base_url), data=body,
                              auth=HTTPBasicAuth(self._client_id, self._client_secret), headers=headers, timeout=10)
            r.raise_for_status()
            message = r.json()
            return message['access_token']
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            raise ObeliskError("Could not request access token.")

    @retry_timeout
    def __request_rpt_token(self):
        try:
            access_token = self.__request_access_token()
            headers = {
                'Authorization': 'Bearer {}'.format(access_token),
                'Content-Type': 'application/x-www-form-urlencoded'

            }
            payload = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
                'audience': 'policy-enforcer',
            }
            r = requests.post("{}/auth/realms/idlab-iot/protocol/openid-connect/token".format(self._base_url), data=payload,
                              headers=headers, timeout=10)
            r.raise_for_status()
            message = r.json()
            self._rpt_token = message['access_token']
            self._rpt_refresh_token = message['refresh_token']
            self._rpt_refresh_token_expire_date = datetime.utcnow(
            ) + timedelta(seconds=message['refresh_expires_in'])
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            raise ObeliskError("Could not request RPT token.")

    @retry_timeout
    def __refresh_rpt_token(self):
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            payload = {
                'grant_type': 'refresh_token',
                'refresh_token': self._rpt_refresh_token,
                'client_id': self._client_id,
                'client_secret': self._client_secret,
            }
            r = requests.post("{}/auth/realms/idlab-iot/protocol/openid-connect/token".format(
                self._base_url), headers=headers, data=payload, timeout=10)
            r.raise_for_status()
            message = r.json()
            self._rpt_token = message['access_token']
            self._rpt_refresh_token = message['refresh_token']
            self._rpt_refresh_token_expire_date = datetime.utcnow(
            ) + timedelta(seconds=message['refresh_expires_in'])
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            raise ObeliskError("Could not refresh RPT token.")

    @retry_timeout
    def send_to_obelisk(self, data, refresh_rpt=False):
        try:
            if refresh_rpt:
                if not self._rpt_refresh_token_expire_date or self._rpt_refresh_token_expire_date < datetime.utcnow():
                    self.__request_rpt_token()
                else:
                    self.__refresh_rpt_token()
            headers = {'Content-Type': 'application/json',
                       'Authorization': 'Bearer {}'.format(self._rpt_token)}
            url = "{}/api/{}/scopes/{}/ingest?precision={}".format(
                self._base_url, self._version, self._scope_id, obelisk_precisions[self._precision])
            resp = requests.post(url, json=data, headers=headers, timeout=10)
            if resp.status_code == 403 or resp.status_code == 401:
                logger.debug("Requesting/renewing RPT token")
                self.send_to_obelisk(data, refresh_rpt=True)
            else:
                resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            raise ObeliskError("Could not send data to Obelisk.")

    @retry_timeout
    def retrieve_last_value_from_obelisk(self, metrics_id, thing_id, refresh_rpt=False):
        try:
            # Check the need to refresh the rpt token    
            if refresh_rpt:
                if not self._rpt_refresh_token_expire_date or self._rpt_refresh_token_expire_date < datetime.utcnow():
                    self.__request_rpt_token()
                else:
                    self.__refresh_rpt_token()

            # Specify necessary request information        
            headers = {'Content-Type': 'application/json',
                       'Authorization': 'Bearer {}'.format(self._rpt_token)}
            url = "{}/api/{}/scopes/{}/metrics/{}/events/latest?filter=sourceId%3D{}".format(self._base_url, self._version, self._scope_id, metrics_id,thing_id)

            # The request
            resp = requests.get(url, headers=headers, timeout=10)
            # In case of issues with the token refresh and retry          
            if resp.status_code == 403 or resp.status_code == 401:
                logger.debug("Requesting/renewing RPT token")
                respjson=self.retrieve_last_value_from_obelisk(metrics_id, thing_id, refresh_rpt=True)
            else:
                resp.raise_for_status()
                respjson=resp.json()
            
            # Return the result
            return respjson
        
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            raise ObeliskError("Could not retrieve last value for thing {} from Obelisk.".format(thing_id))
            
    @retry_timeout
    def retrieve_series_from_obelisk(self, metrics_id, thing_id, from_datetime, to_datetime=datetime.now(), refresh_rpt=False):
        try:
            # first check if the dates are provide in the proper datetime format
            if not isinstance(from_datetime,datetime):
                raise ObeliskDateTimeTypeError("From date is not of the correct type. Should be datetime.datetime")
            else:
                FromDateTimestamp=round(from_datetime.timestamp()*1000)
            if not isinstance(to_datetime,datetime):
                raise ObeliskDateTimeTypeError("To date is not of the correct type. Should be datetime.datetime")
            else:
                ToDateTimestamp=round(to_datetime.timestamp()*1000)
            
            # Check the need to refresh the rpt token    
            if refresh_rpt:
                if not self._rpt_refresh_token_expire_date or self._rpt_refresh_token_expire_date < datetime.utcnow():
                    self.__request_rpt_token()
                else:
                    self.__refresh_rpt_token()
            
            # Specify necessary request information        
            headers = {'Content-Type': 'application/json',
                       'Authorization': 'Bearer {}'.format(self._rpt_token)}
            
            url = "{}/api/{}/scopes/{}/metrics/{}/events?filter=sourceId%3D{}&from={}&to={}".format(self._base_url, self._version, self._scope_id,metrics_id,thing_id,FromDateTimestamp,ToDateTimestamp)
            
            # The request
            resp = requests.get(url, headers=headers, timeout=10)
            # In case of issues with the token refresh and retry
            if resp.status_code == 403 or resp.status_code == 401:
                logger.debug("Requesting/renewing RPT token")
                respjson=self.retrieve_series_from_obelisk(metrics_id, thing_id, from_datetime, to_datetime, refresh_rpt=True)
            else:
                resp.raise_for_status()
                respjson=resp.json()
            
            # Return the result
            return respjson
        
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            raise ObeliskError("Could not retrieve values for thing {} for the specified period from Obelisk.".format(thing_id))
