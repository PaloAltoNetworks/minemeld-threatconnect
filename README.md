# threatconnect-miner
Extension for [Threat Connect](https://docs.threatconnect.com "Threat Connect API")

## Configuration

Create a new prototype using threatconnect.Miner as a base and add the following mandatory configuration attributes (provided by Threat Connect):
*  apikey
*  apisecret

Optional configuration attributes:
* sandbox (true|*false*) : Use Threat Connect's SandBox instead of the Public Cloud.
* owner : The data owner of the indicators to be extracted.

## Installation

Add it as an external extension as introduced in [MineMeld 0.9.32](https://live.paloaltonetworks.com/t5/MineMeld-Discussions/What-s-new-in-MineMeld-0-9-32/td-p/141261 "What's new in MineMeld 0.9.32")

Use the **git** option with the URL of this repository ( https://github.com/PaloAltoNetworks/minemeld-threatconnect.git )