# py-electrolux-ocp

Python package wrapper around Electrolux OneApp (OCP) api

Early version, this package APIs might change

## Prerequisites

```
pip install aiohttp
pip install pyelectroluxocp
```

## Usage examples

Example to connect via websockets and listen for appliance state changes
```py
import asyncio
import json
from pyelectroluxocp import OneAppApi

async def main():
    async with OneAppApi("__username__", "__password__") as client:
        appliances = await client.get_appliances_list()

        print("appliances found: ", json.dumps([x.get("applianceData").get("applianceName")+" "+x.get("applianceId") for x in appliances]))

        def state_update_callback(a):
            print("appliance state updated", json.dumps((a)))
        await client.watch_for_appliance_state_updates([appliances[0].get("applianceId")], state_update_callback)

asyncio.run(main())
```

## TODOs

- Better error messages on known scenarios (login failed)

