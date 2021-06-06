# tasmota-sip
xdrv for tasmota implementing simple sip client. Calls sip phone on door bell. You can call any number if door bell gets activated. 
This may be an external number, internal handset or \*\*9 for all internal hand sets.

## History
- V1 First public version

## Installation
You will have to compile tasmota to integrate the file xdrv_92_sip.ino
First step is to clone tasmota from [github projectpage](https://github.com/arendst/tasmota/)

In user_config_override.h ```#define USE_SIP```

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
USE_RULES must be defined to borrow MEM1-MEM5 as config variables. To set enter MEM1 value into web console.

- MEM1 dial_nr
- MEM2 dial_user
- MEM3 user
- MEM4 password
- MEM5 ipStr

## Webinterface
![web interface](/images/webif.jpg)


