# tasmota-sip
xdrv for tasmota implementing simple sip client. Calls sip phone on door bell.

## History
- V1 First public version

## Installation
You will have to compile tasmota to integrate the file xdrv_92_sip.ino
First step is to clone tasmota from [github projectpage](https://github.com/arendst/tasmota/)

## Hardware
![door bell interface](https://github.com/gkle/tasmota-sip/blob/main/images/klingel.jpg)

## Commands
- siptest simulate door bell
- sipset <option>=<value> without =<value> shows current option
  -- option pwd set password

