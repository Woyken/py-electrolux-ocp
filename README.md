# py-electrolux-ocp

## ARCHIVED

This repository has been archived and is no longer maintained.

Electrolux has released an official SDK for their API. 
Please use the official repository instead:

https://github.com/electrolux-oss/electrolux-group-developer-sdk

Official API Documentation:
https://developer.electrolux.one/documentation/reference

This project was created as a reverse-engineered wrapper before the official API was available. Now that Electrolux provides official support and documentation, this repository is no longer necessary.

Thank you to everyone who used and contributed to this project!

## What is this

Python package wrapper around Electrolux OneApp (OCP) api

Early version, this package APIs might change

## Prerequisites

```
pip install pyelectroluxocp
```

## Usage examples

Example to connect via websockets and listen for appliance state changes
```py
import asyncio
import json
from pyelectroluxocp import OneAppApi

async def main():
    async with OneAppApi("__username__", "__password__", "fr") as client:
        appliances = await client.get_appliances_list()

        print("appliances found: ", json.dumps([x.get("applianceData").get("applianceName")+" "+x.get("applianceId") for x in appliances]))

        def state_update_callback(a):
            print("appliance state updated", json.dumps((a)))
        await client.watch_for_appliance_state_updates([appliances[0].get("applianceId")], state_update_callback)

asyncio.run(main())
```

