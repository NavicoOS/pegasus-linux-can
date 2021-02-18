# Pegasus Linux Device  Driver

The goal is to have a kernel driver for the CAN stack.
This is currently a WIP.
It currently grab the custom USB interface, and allow to read/write over bulk USB transfer from a char device.

Here is how to probe for Pegasus custom "get descriptor" command:
```
# Build and load module
$ make && sudo make test
# Send get_descriptor command, and read the answer (10 bytes)
$ echo -ne '\x04\x01\x00\x05' | sudo dd of=/dev/pegasus0 && sudo dd if=/dev/pegasus0 bs=14 count=1 | hexdump -C 
0+1 records in
0+1 records out
4 bytes copied, 0.000275549 s, 14.5 kB/s
1+0 records in
1+0 records out
14 bytes copied, 0.000281993 s, 49.6 kB/s
00000000  0e 01 00 05 0d 00 ec 03  00 00 ff ff ff ff        |..............|
0000000e
# 0d 00 means v0.13, ec03 is platfrom ID, 00 00 is Board Id, and ffffffff is serial number
# This can be query with https://bitbucket.navico.com/users/christian.gagneraud/repos/pegasus-linux-poc
$ sudo ./venv/bin/python3 ../pegasus.py  
Firmware version: v0.13
Serial number:    0xFFFFFFFF
PlatformId:       0x03EC
BoardId:          0x0000
^C
Counters: Rx=0, Tx=0, Err=0
$ dmesg | tail
[436640.871434] usbcore: registered new interface driver pegasus_usb
[436644.370172] usb 1-1: new full-speed USB device number 89 using xhci_hcd
[436644.520028] usb 1-1: New USB device found, idVendor=1cda, idProduct=03e8
[436644.520034] usb 1-1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[436644.520038] usb 1-1: Product: Navico USB IO Computer
[436644.520042] usb 1-1: Manufacturer: Navico Asia Pacific Ltd
[436644.520045] usb 1-1: SerialNumber: SN-03EC-FFFFFFFF
[436644.522974] input: Navico Asia Pacific Ltd Navico USB IO Computer as /devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/0003:1CDA:03E8.004B/input/input114
[436644.583235] hid-generic 0003:1CDA:03E8.004B: input,hidraw0: USB HID v1.01 Keyboard [Navico Asia Pacific Ltd Navico USB IO Computer] on usb-0000:00:14.0-1/input0
[436644.584859] input: Navico Asia Pacific Ltd Navico USB IO Computer as /devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.1/0003:1CDA:03E8.004C/input/input115
[436644.585347] hid-generic 0003:1CDA:03E8.004C: input,hidraw1: USB HID v1.01 Mouse [Navico Asia Pacific Ltd Navico USB IO Computer] on usb-0000:00:14.0-1/input1
[436644.586083] pegasus_usb 1-1:1.2: USB Pegasus device now attached to pegasus0
[436647.954843] pegasus_usb 1-1:1.2: WRITE count=4
[436647.954864] pegasus_usb 1-1:1.2: WRITE rv=0
[436647.954938] pegasus_usb 1-1:1.2: WRITE CB
[436647.977250] pegasus_usb 1-1:1.2: READ count=14
[436647.977258] pegasus_usb 1-1:1.2: pegasus_do_read_io count=14
[436647.977381] pegasus_usb 1-1:1.2: READ CB
[436647.977434] pegasus_usb 1-1:1.2: READ rv=14
```

