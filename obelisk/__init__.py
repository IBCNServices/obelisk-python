from obelisk.obeliskclient import Obelisk, ObeliskError, ObeliskPrecisions

import logging
from logging import NullHandler

logging.getLogger(__name__).addHandler(NullHandler())

__all__ = [
    Obelisk,
    ObeliskError,
    ObeliskPrecisions,
]

__version__ = '0.0.1'