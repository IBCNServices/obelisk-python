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