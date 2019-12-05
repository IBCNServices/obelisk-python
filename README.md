# Obelisk Python Client

Client library for the [Obelisk project](https://obelisk.ilabt.imec.be).

## Example

```python
from obelisk import Obelisk, ObeliskPrecisions

obe = Obelisk(base_url="https://obelisk.ilabt.imec.be",
              client_id="CLIENT_ID",
              client_secret="CLIENT_SECRET",
              scope_id="SCOPE_ID",
              precision=ObeliskPrecisions.MILLISECONDS)

data = [
    [1569369600000, 'temperature', 'aaaaaaaaa', 0]
]

obe.send_to_obelisk(data)
```

## Logging configuration

By default, obelisk logs to the 'obelisk' logger. By default, this logger is configured with a NullHandler, so there will be nothing output unless you configure a handler. Programmatically, this might be accomplished with something as simple as:
```python
logging.getLogger('obelisk').addHandler(logging.StreamHandler())
```
Change the logging level via:
```python
logging.getLogger('obelisk').setLevel(logging.ERROR)
```