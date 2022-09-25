# tasmota-sip
xdrv for tasmota implementing simple sip client. Calls sip phone on door bell. You can call any number if door bell gets activated. 
This may be an external number, internal handset or \*\*9 for all internal hand sets.

## History
- V1 First public version
- 2022-10-25 Upgrade to Tasmota V12.1.1

## Installation
You will have to compile tasmota to integrate the file xdrv_92_sip.ino
First step is to clone tasmota from [github projectpage](https://github.com/arendst/tasmota/)
Copy file xdrv_92_sip.ino into directory tasmota_xdrv_driver.

Create file user_config_override.h from user_config_override_sample.h adding ```#define USE_SIP``` and USE_RULES.

## Hardware
PIR1 and BMP280 are optional. For U2 i have used a cheep step down converter. Also U3 opto coupler may also be replaced by handy one.
![door bell interface](/images/klingel.jpg)

## Commands
There are a limited number of commands you can enter into web console.

- siptest	simulates door bell.
- sipstate	shows current state. May also be changed if followed by integer value. Error states are greater than 1000 and do indicate line of error (substitude 1000).
- sipset option=value	without =value shows current option. Available options are:
  - dial_nr	number that will be called on door bell
  - dial_user shows up at handset if supported by handset
  - peer sip server
  - realm 	same as peer
  - myip 	get set on init
  - user 	fritzbox user. You should create one
  - pwd 		fritzbox user password
  - ipStr 	fritzbox ip
  - port 	fritzbox port. Default 5060

## Configuration
![IO configuration](/images/configuration.jpg)

To permanently save changed settings we borrow configuration variables from rules modul. You will have to restart tasmota or use sipset command.
USE_RULES must be defined to borrow MEM1-MEM5 as config variables. To set enter MEMx value into web console. MEM will show current setting.

- MEM1 dial_nr
- MEM2 dial_user
- MEM3 user
- MEM4 password
- MEM5 ipStr

## Webinterface
![web interface](/images/webif.jpg)


