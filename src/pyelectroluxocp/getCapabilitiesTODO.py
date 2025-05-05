import asyncio
import json
from typing import Any, Dict, Literal, Optional, TypedDict, Union, cast

from .apiModels import ApplienceStatusResponse
from .oneAppApi import OneAppApi


class TriggerActionValue(TypedDict):
    disabled: bool
    # ... other override values for this field


class TriggerCondition(TypedDict):
    operand_1: Union[str, "TriggerCondition"]
    operand_2: Union[str, "TriggerCondition"]
    operator: Literal["eq", "and", "or"]


class Trigger(TypedDict):
    action: Dict[str, TriggerActionValue]
    condition: TriggerCondition


class Capability(TypedDict):
    access: Literal["read", "write", "readwrite"]
    triggers: Optional[list[Trigger]]
    type: Literal["number", "string", "boolean", "alert", "complex"]
    values: Dict[str, Any]
    max: Optional[int]
    min: Optional[int]
    step: Optional[int]


class AvailableCapability(TypedDict):
    capabilityType: Optional[Literal["number", "string", "boolean", "alert", "complex"]]
    defaultAccess: Optional[Literal["read", "write", "readwrite"]]
    allPossibleValues: Optional[Dict[str, Any]]
    triggerAction: Optional[TriggerActionValue]


def flatten_json(y: Dict[str, Any]):
    out: Dict[str, Any] = {}

    def flatten(x: Dict[str, Any], name: str = ""):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + "/")
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


class ParsedPossibleProperty(TypedDict):
    defaultAccess: Literal["read", "write", "readwrite"]
    accessOverride: Optional[Literal["read", "write", "readwrite"]]
    default: Optional[Union[str, int, bool]]
    type: str


def parse_capabilities(
    capabilitiesResponse: Dict[str, Capability],
    currentProperties: ApplienceStatusResponse,
):
    # step through capabilities
    # find "values" for all possible values
    # type: string, number or complex
    # access: read write readwrite
    # triggers: [] condition to validate, action will enable or disable some possible values for other fields

    flatCurrentProperties = flatten_json(currentProperties["properties"]["reported"])

    def parse_trigger_condition(
        triggerCondition: str | TriggerCondition, currentContextName: str
    ):
        if isinstance(triggerCondition, str):
            currentValue = flatCurrentProperties[triggerCondition]
            if isinstance(currentValue, bool):
                return currentValue
            raise Exception(
                "Do not pass non bool conditions to parse_trigger_condition"
            )

        # TODO, handle "$self" action
        if triggerCondition["operator"] == "eq":
            operand1 = triggerCondition["operand_1"]
            if operand1 == "value":
                operand1Value = flatCurrentProperties[currentContextName]
            operand1 = currentContextName if operand1 == "value" else operand1
            operand2 = triggerCondition["operand_2"]
            # Assume operand2 is always value to compare against
            operand2Value = operand2
            if isinstance(operand1, str):
                operand1Value = flatCurrentProperties[operand1]
            else:
                raise Exception(
                    "Don't know what to do with eq and operand 1 object",
                    operand1,
                    trigger,
                    triggerCondition,
                )
            if (
                type(operand1Value) is type(operand2Value)
                and operand1Value == operand2Value
            ):
                return True
        if triggerCondition["operator"] == "or":
            operand1 = triggerCondition["operand_1"]
            operand1 = currentContextName if operand1 == "value" else operand1
            operand2 = triggerCondition["operand_2"]
            operand2 = currentContextName if operand2 == "value" else operand2
            # if it's string assume it will have value of bool
            if parse_trigger_condition(operand1, currentContextName):
                return True
            if parse_trigger_condition(operand2, currentContextName):
                return True
        if triggerCondition["operator"] == "and":
            operand1 = triggerCondition["operand_1"]
            operand1 = currentContextName if operand1 == "value" else operand1
            operand2 = triggerCondition["operand_2"]
            operand2 = currentContextName if operand2 == "value" else operand2
            # if it's string assume it will have value of bool
            if parse_trigger_condition(operand1, currentContextName):
                if parse_trigger_condition(operand2, currentContextName):
                    return True
        return False

    availableCapabilities: Dict[str, AvailableCapability] = dict()

    def flattenCapabilityIfNecessary(capabilities: Dict[str, Capability]):
        for capabilityKey, capabilityValue in capabilities.items():
            if capabilityValue.get("type") is None:
                for nestedKey, nestedValue in capabilityValue.items():
                    if nestedValue.get("type") is None:
                        continue
                    yield (
                        f"{capabilityKey}/{nestedKey}",
                        cast(Capability, nestedValue),
                    )
                continue
            yield (capabilityKey, capabilityValue)

    capabilityItems = flattenCapabilityIfNecessary(capabilitiesResponse)

    # activeTriggerActions: Dict[str, list[TriggerActionValue]] = dict()

    for capabilityKey, capabilityValue in capabilityItems:
        # TODO probably need to pass capabilities to trigger condition parser
        # find type by name and then compare if type matches

        # print('capability value:', capabilityValue)

        # TODO networkInterface is nested... sad
        capabilityType = capabilityValue["type"]
        defaultAccess = capabilityValue["access"]
        allPossibleValues = capabilityValue.get("values")
        # TODO "values" field contains inner overrides, ex: "userSelections/programUID":"values":"BLANKET_PR_DUVET":"startTime":"access": "readwrite"
        if availableCapabilities.get(capabilityKey) is None:
            availableCapabilities[capabilityKey] = {
                "allPossibleValues": allPossibleValues,
                "capabilityType": capabilityType,
                "defaultAccess": defaultAccess,
                "triggerAction": None,
            }
        else:
            availableCapabilities[capabilityKey] = {
                "allPossibleValues": allPossibleValues,
                "capabilityType": capabilityType,
                "defaultAccess": defaultAccess,
                "triggerAction": availableCapabilities[capabilityKey]["triggerAction"],
            }
        triggers = capabilityValue.get("triggers")
        if triggers is not None:
            for trigger in triggers:
                if parse_trigger_condition(trigger["condition"], capabilityKey):
                    print("ACTIVE TRIGGER", trigger["action"])
                    # todo, action "activate", enable disable other fields
                    action = trigger["action"]
                    for targetCapabilityKey, targetCapabilityValues in action.items():
                        # if activeTriggerActions.get(targetCapabilityKey) is None:
                        #     activeTriggerActions[targetCapabilityKey] = [
                        #         targetCapabilityValues
                        #     ]
                        # else:
                        #     activeTriggerActions[targetCapabilityKey].append(
                        #         targetCapabilityValues
                        #     )
                        if availableCapabilities.get(targetCapabilityKey) is None:
                            availableCapabilities[targetCapabilityKey] = {
                                "triggerAction": targetCapabilityValues,
                                "allPossibleValues": None,
                                "capabilityType": None,
                                "defaultAccess": None,
                            }
                        elif (
                            availableCapabilities[targetCapabilityKey].get(
                                "triggerAction"
                            )
                            is None
                        ):
                            availableCapabilities[targetCapabilityKey][
                                "triggerAction"
                            ] = targetCapabilityValues
                        else:
                            # TODO either merge or save a list of active actions
                            merged: Any = dict()
                            # merged.get()
                            merged.update(
                                availableCapabilities[targetCapabilityKey][
                                    "triggerAction"
                                ]
                            )
                            merged.update(targetCapabilityValues)
                            availableCapabilities[targetCapabilityKey][
                                "triggerAction"
                            ] = merged

                    # if trigger["condition"]["operator"] == "eq":
                    #     operand1 = trigger["condition"]["operand1"]
                    #     operand1 = capabilityKey if operand1 == "value" else operand1
                    #     operand2 = trigger["condition"]["operand2"]
                    #     operand2 = capabilityKey if operand2 == "value" else operand2
                    #     if isinstance(operand1, str):
                    #         operand1Value = flatCurrentProperties[operand1]
                    #     else:
                    #         raise Exception(
                    #             "Don't know what to do with eq and operand 1 object"
                    #         )
                    #     if isinstance(operand2, str):
                    #         operand2Value = flatCurrentProperties[operand2]
                    #     else:
                    #         raise Exception(
                    #             "Don't know what to do with eq and operand 2 object"
                    #         )

                    #     if (
                    #         type(operand1Value) is type(operand2Value)
                    #         and operand1Value == operand2Value
                    #     ):
                    #         pass
                    pass
                pass

        pass
    # return {
    #     "availableCapabilities": availableCapabilities,
    #     "activeTriggerActions": activeTriggerActions,
    # }
    return availableCapabilities
    pass


async def main():
    client = OneAppApi("test", "test")
    appliances = await client.get_appliances_list(True)
    capabilities = await client.get_appliance_capabilities(
        appliances[0].get("applianceId")
    )
    state = await client.get_appliance_state(appliances[0].get("applianceId"), False)
    # print("aaaaaaaaaaaaaaaaaaaaaaaaaaaa", json.dumps(state))
    print(json.dumps(parse_capabilities(capabilities, state)))


asyncio.run(main())
