# TALQ 2.7.1 Gateway Conformance Gap Analysis

**Repository:** FlowSense TALQ Gateway
**Target specification:** TALQ Smart City Gateway API 2.7.1
**Specification source:** https://github.com/TALQ-consortium/TALQ_specification/blob/main/oas/talq-api-gateway-2-7-1-online.json
**Status:** Gap analysis only; this project is not yet TALQ-conformant or certified.

## Findings from the current code

- Official Gateway OpenAPI specification defines **62 paths and 129 HTTP operations**.
- Current app/main.py implements only a small subset and returns custom placeholder response shapes for several TALQ-looking routes.
- The current clientAddress is an arbitrary string (String(160) and test value cms-example-01), but TALQ 2.7.1 expects UUID-formatted client addresses on operations where the spec declares that parameter.
- talq-api-version is hard-coded to 2.7.1, but this alone does not make the routes, schemas, error responses, or behavior conformant.
- Device/data-package collections are hard-coded empty lists. The gateway is not connected to the FlowSense sensor/meter data model.
- The product profile and the mapping from FlowSense energy/water readings to TALQ device functions and attributes must be agreed before meaningful conformance can be implemented.
- The current authentication/access-request API is a custom partner-onboarding layer. It can remain as an adapter security layer, but it must not change the official TALQ request/response contracts.

## Required implementation work

1. Select the TALQ profile(s) actually supported by FlowSense. Do not claim all profiles by default.
2. Define stable UUIDs for the gateway/client address and every TALQ device address; do not use organization slugs as protocol addresses.
3. Map the existing FlowSense backend readings to TALQ data-model entities and required functions/attributes, preserving source timestamps, units, and measurement semantics.
4. Implement the profile-required Gateway operations and exact request/response schemas from the official OpenAPI files.
5. Implement correct status codes, pagination, request IDs, validation errors, asynchronous operation behavior where specified, and resource lifecycle semantics.
6. Keep the current API-key onboarding/revocation layer, but validate partner keys independently from TALQ protocol validation.
7. Add automated schema/contract tests and end-to-end tests against real mapped FlowSense data.
8. Run the TALQ Consortium's required test/certification process before claiming certified compliance.

## Official operation inventory

The table lists all operations from the pinned TALQ 2.7.1 Gateway OpenAPI file. Mandatory profiles reflects the specification's x-talq-mandatory metadata for the Gateway side; requirements vary by profile.

| Method | Path | Operation ID | Mandatory Gateway profiles |
|---|---|---|---|
| GET | /assign-commands | getAssignCommands | None marked |
| POST | /assign-commands | assignCommand | None marked |
| GET | /bracket-types | getBracketTypes | None marked |
| POST | /bracket-types | addBracketTypes | None marked |
| PUT | /bracket-types | updateBracketTypes | None marked |
| GET | /bracket-types/count | getBracketTypesCount | None marked |
| DELETE | /bracket-types/{bracketTypeAddress} | deleteBracketType | None marked |
| GET | /bracket-types/{bracketTypeAddress} | getBracketType | None marked |
| PUT | /bracket-types/{bracketTypeAddress} | updateBracketType | None marked |
| GET | /calendars | getCalendars | None marked |
| POST | /calendars | addCalendars | None marked |
| PUT | /calendars | updateCalendars | None marked |
| GET | /calendars/count | getCalendarsCount | None marked |
| DELETE | /calendars/{calendarAddress} | deleteCalendar | None marked |
| GET | /calendars/{calendarAddress} | getCalendar | None marked |
| PUT | /calendars/{calendarAddress} | updateCalendar | None marked |
| GET | /control-programs | getControlPrograms | None marked |
| POST | /control-programs | addControlPrograms | None marked |
| PUT | /control-programs | updateControlPrograms | None marked |
| GET | /control-programs/count | getControlProgramsCount | None marked |
| DELETE | /control-programs/{controlProgramAddress} | deleteControlProgram | None marked |
| GET | /control-programs/{controlProgramAddress} | getControlProgram | None marked |
| PUT | /control-programs/{controlProgramAddress} | updateControlProgram | None marked |
| GET | /controller-types | getControllerTypes | None marked |
| POST | /controller-types | addControllerTypes | None marked |
| PUT | /controller-types | updateControllerTypes | None marked |
| GET | /controller-types/count | getControllerTypesCount | None marked |
| DELETE | /controller-types/{controllerTypeAddress} | deleteControllerType | None marked |
| GET | /controller-types/{controllerTypeAddress} | getControllerType | None marked |
| PUT | /controller-types/{controllerTypeAddress} | updateControllerType | None marked |
| GET | /data-packages | getDataPackages | None marked |
| PUT | /data-packages | upgradeDataPackages | None marked |
| GET | /device-classes | getDeviceClasses | None marked |
| GET | /device-classes/count | getDeviceClassesCount | None marked |
| GET | /device-classes/{className} | getDeviceClass | None marked |
| GET | /devices | getDevices | None marked |
| PATCH | /devices | partialUpdateDevices | None marked |
| POST | /devices | addDevices | None marked |
| PUT | /devices | updateDevices | None marked |
| GET | /devices/count | getDevicesCount | None marked |
| DELETE | /devices/{deviceAddress} | deleteDevice | None marked |
| GET | /devices/{deviceAddress} | getDevice | None marked |
| PATCH | /devices/{deviceAddress} | partialUpdateDevice | None marked |
| GET | /devices/{deviceAddress}/{functionId} | getDeviceFunction | None marked |
| PATCH | /devices/{deviceAddress}/{functionId} | partialUpdateFunction | None marked |
| GET | /devices/{deviceAddress}/{functionId}/{attributeName} | getDeviceAttribute | None marked |
| PATCH | /devices/{deviceAddress}/{functionId}/{attributeName} | partialUpdateAttribute | None marked |
| GET | /driver-types | getDriverTypes | None marked |
| POST | /driver-types | addDriverTypes | None marked |
| PUT | /driver-types | updateDriverTypes | None marked |
| GET | /driver-types/count | getDriverTypesCount | None marked |
| DELETE | /driver-types/{driverTypeAddress} | deleteDriverType | None marked |
| GET | /driver-types/{driverTypeAddress} | getDriverType | None marked |
| PUT | /driver-types/{driverTypeAddress} | updateDriverType | None marked |
| GET | /groups | getGroups | None marked |
| POST | /groups | addGroups | None marked |
| PUT | /groups | updateGroups | None marked |
| GET | /groups/count | getGroupsCount | None marked |
| DELETE | /groups/{groupAddress} | deleteGroup | None marked |
| GET | /groups/{groupAddress} | getGroup | None marked |
| PUT | /groups/{groupAddress} | updateGroup | None marked |
| PUT | /groups/{groupAddress}/members | addGroupMembers | None marked |
| GET | /groups/{groupAddress}/members/count | getGroupMembersCount | None marked |
| DELETE | /groups/{groupAddress}/members/{memberResource}/{memberAddress} | deleteGroupMember | None marked |
| GET | /lamp-types | getLampTypes | None marked |
| POST | /lamp-types | addLampTypes | None marked |
| PUT | /lamp-types | updateLampTypes | None marked |
| GET | /lamp-types/count | getLampTypesCount | None marked |
| DELETE | /lamp-types/{lampTypeAddress} | deleteLampType | None marked |
| GET | /lamp-types/{lampTypeAddress} | getLampType | None marked |
| PUT | /lamp-types/{lampTypeAddress} | updateLampType | None marked |
| GET | /log-reports/count | getLogReportsCount | None marked |
| GET | /log-reports/{loggerAddress} | getLogReport | None marked |
| POST | /logger-configs | addLoggerConfig | None marked |
| DELETE | /logger-configs/{loggerAddress} | deleteLoggerConfig | None marked |
| GET | /logger-configs/{loggerAddress} | getLoggerConfig | None marked |
| PUT | /logger-configs/{loggerAddress} | updateLoggerConfig | None marked |
| GET | /luminaire-types | getLuminaireTypes | None marked |
| POST | /luminaire-types | addLuminaireTypes | None marked |
| PUT | /luminaire-types | updateLuminaireTypes | None marked |
| GET | /luminaire-types/count | getLuminaireTypesCount | None marked |
| DELETE | /luminaire-types/{luminaireTypeAddress} | deleteLuminaireType | None marked |
| GET | /luminaire-types/{luminaireTypeAddress} | getLuminaireType | None marked |
| PUT | /luminaire-types/{luminaireTypeAddress} | updateLuminaireType | None marked |
| POST | /override-commands | sendCommand | None marked |
| GET | /services | getServices | None marked |
| GET | /services/{serviceName} | getService | None marked |
| GET | /control-device-dali-part103-types | getControlDeviceDaliPart103Types | None marked |
| POST | /control-device-dali-part103-types | addControlDeviceDaliPart103Types | None marked |
| PUT | /control-device-dali-part103-types | updateControlDeviceDaliPart103Types | None marked |
| GET | /control-device-dali-part103-types/count | getControlDeviceDaliPart103TypesCount | None marked |
| GET | /control-device-dali-part103-types/{controlDeviceDaliPart103TypeAddress} | getControlDeviceDaliPart103Type | None marked |
| PUT | /control-device-dali-part103-types/{controlDeviceDaliPart103TypeAddress} | updateControlDeviceDaliPart103Type | None marked |
| DELETE | /control-device-dali-part103-types/{controlDeviceDaliPart103TypeAddress} | deleteControlDeviceDaliPart103Type | None marked |
| GET | /control-gear-dali-part102-types | getControlGearDaliPart102Types | None marked |
| POST | /control-gear-dali-part102-types | addControlGearDaliPart102Types | None marked |
| PUT | /control-gear-dali-part102-types | updateControlGearDaliPart102Types | None marked |
| GET | /control-gear-dali-part102-types/count | getControlGearDaliPart102TypesCount | None marked |
| GET | /control-gear-dali-part102-types/{controlGearDaliPart102TypeAddress} | getControlGearDaliPart102Type | None marked |
| PUT | /control-gear-dali-part102-types/{controlGearDaliPart102TypeAddress} | updateControlGearDaliPart102Type | None marked |
| DELETE | /control-gear-dali-part102-types/{controlGearDaliPart102TypeAddress} | deleteControlGearDaliPart102Type | None marked |
| GET | /luminaire-data-dali-part251-types | getLuminaireDataDaliPart251Types | None marked |
| POST | /luminaire-data-dali-part251-types | addLuminaireDataDaliPart251Types | None marked |
| PUT | /luminaire-data-dali-part251-types | updateLuminaireDataDaliPart251Types | None marked |
| GET | /luminaire-data-dali-part251-types/count | getLuminaireDataDaliPart251TypesCount | None marked |
| GET | /luminaire-data-dali-part251-types/{luminaireDataDaliPart251TypeAddress} | getLuminaireDataDaliPart251Type | None marked |
| PUT | /luminaire-data-dali-part251-types/{luminaireDataDaliPart251TypeAddress} | updateLuminaireDataDaliPart251Type | None marked |
| DELETE | /luminaire-data-dali-part251-types/{luminaireDataDaliPart251TypeAddress} | deleteLuminaireDataDaliPart251Type | None marked |
| GET | /energy-data-dali-part252-types | getEnergyDataDaliPart252Types | None marked |
| POST | /energy-data-dali-part252-types | addEnergyDataDaliPart252Types | None marked |
| PUT | /energy-data-dali-part252-types | updateEnergyDataDaliPart252Types | None marked |
| GET | /energy-data-dali-part252-types/count | getEnergyDataDaliPart252TypesCount | None marked |
| GET | /energy-data-dali-part252-types/{energyDataDaliPart252TypeAddress} | getEnergyDataDaliPart252Type | None marked |
| PUT | /energy-data-dali-part252-types/{energyDataDaliPart252TypeAddress} | updateEnergyDataDaliPart252Type | None marked |
| DELETE | /energy-data-dali-part252-types/{energyDataDaliPart252TypeAddress} | deleteEnergyDataDaliPart252Type | None marked |
| GET | /diagnostics-and-maintenance-data-dali-part253-types | getDiagnosticsAndMaintenanceDataDaliPart253Types | None marked |
| POST | /diagnostics-and-maintenance-data-dali-part253-types | addDiagnosticsAndMaintenanceDataDaliPart253Types | None marked |
| PUT | /diagnostics-and-maintenance-data-dali-part253-types | updateDiagnosticsAndMaintenanceDataDaliPart253Types | None marked |
| GET | /diagnostics-and-maintenance-data-dali-part253-types/count | getDiagnosticsAndMaintenanceDataDaliPart253TypesCount | None marked |
| GET | /diagnostics-and-maintenance-data-dali-part253-types/{diagnosticsAndMaintenanceDataDaliPart253TypeAddress} | getDiagnosticsAndMaintenanceDataDaliPart253Type | None marked |
| PUT | /diagnostics-and-maintenance-data-dali-part253-types/{diagnosticsAndMaintenanceDataDaliPart253TypeAddress} | updateDiagnosticsAndMaintenanceDataDaliPart253Type | None marked |
| DELETE | /diagnostics-and-maintenance-data-dali-part253-types/{diagnosticsAndMaintenanceDataDaliPart253TypeAddress} | deleteDiagnosticsAndMaintenanceDataDaliPart253Type | None marked |
| GET | /luminaire-mounted-control-device-dali-part351-types | getLuminaireMountedControlDeviceDaliPart351Types | None marked |
| POST | /luminaire-mounted-control-device-dali-part351-types | addLuminaireMountedControlDeviceDaliPart351Types | None marked |
| PUT | /luminaire-mounted-control-device-dali-part351-types | updateLuminaireMountedControlDeviceDaliPart351Types | None marked |
| GET | /luminaire-mounted-control-device-dali-part351-types/count | getLuminaireMountedControlDeviceDaliPart351TypesCount | None marked |
| GET | /luminaire-mounted-control-device-dali-part351-types/{luminaireMountedControlDeviceDaliPart351TypeAddress} | getLuminaireMountedControlDeviceDaliPart351Type | None marked |
| PUT | /luminaire-mounted-control-device-dali-part351-types/{luminaireMountedControlDeviceDaliPart351TypeAddress} | updateLuminaireMountedControlDeviceDaliPart351Type | None marked |
| DELETE | /luminaire-mounted-control-device-dali-part351-types/{luminaireMountedControlDeviceDaliPart351TypeAddress} | deleteLuminaireMountedControlDeviceDaliPart351Type | None marked |

## Critical data dependency

This repository does not contain the FlowSense backend schema or an authenticated service interface to read the real sensor/meter records. The gateway must stay a standalone adapter and should not modify the existing backend, database, MQTT pipeline, or dashboard. To finish real data mapping, the adapter needs the existing data contract/schema and a safe read-only connection method.

## License

The official TALQ specification is distributed under the BSD 3-Clause License. The upstream license is retained at LICENSE-TALQ. Source: https://github.com/TALQ-consortium/TALQ_specification