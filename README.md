BLE-Replay
=============

BLE-Replay is a Bluetooth Low Energy (BLE) peripheral assessment tool. It
pulls/consumes Bluetooth HCI logs from your mobile device and extracts all of
the writes that the central makes to a peripheral. 

This data can be replayed using most Bluetooth dongles from a Linux host, or
saved to disk for modification. This tool gets you straight to testing a
peripheral without extracting data with wireshark or scripting things with
tools like gatttool. It allows for hand-crafting of your own sequences of
characteristic writes to test against a device, including support for
byte-level fuzzing. 

This tool is useful if a mobile app writes some characteristics on the BLE
device in order to configure/unlock/disable some feature or perform some other
state-changing action on the device. 


## Prerequisites

Linux with BlueZ stack.

BLESuite -> https://github.com/nccgroup/BLESuite


## Usage

```bash
python ble-replay.py -h
```

## Replay File Format

```json
["000e", "58e96f71ac901b55", [0,1,5,7], 2]
["002c", "627474686f6c65", [], 1]
["0002", "01", [0], 40]
```
Each line contains a JSON list of 4 parameters:

1. Handle (Hex string)
2. Data (Hex string)
3. Byte positions to fuzz (List of integer offsets, OPTIONAL - use [] to send packet as is)
4. Number of times to fuzz or repeat this write (Integer)

## Examples

Fetch the HCI log from Android device and replay it as is:
```bash
python ble-replay.py -f -r
```

Parse an HCI log from your computer and replay it as is:
```bash
python ble-replay.py -p btsnoop_hci.log -r
```


Fetch the HCI log from Android device and write modifiaBLE replay data to disk:
```bash
python ble-replay.py -f -of replaydata.json
```
Modify the hex values as needed and then play that file using:
```bash
python ble-replay.py -if replaydata.json -r
```
