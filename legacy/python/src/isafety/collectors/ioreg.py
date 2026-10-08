from typing import override

from src.isafety.collectors import ProcessCollectorBase, CollectionDataType


class IORegPlane:
    SERVICE = "IOService"
    DEVICE_TREE = "IODeviceTree"
    USB = "IOUSB"
    FIREWIRE = "IOFireWire"
    POWER = "IOPower"
    PORT = "IOPort"
    WIFI_DIAGNOSTIC = "WiFiDKCoreCapture"
    ACCESSORY = "IOAccessory"
    CORE_CAPTURE = "CoreCapture"


class IORegCollector(ProcessCollectorBase):
    def __init__(self, plane):
        self.plane = plane

    @override
    def type(self):
        return CollectionDataType.PLIST

    @override
    def command(self):
        return ["ioreg", "-p", self.plane, "-l", "-a"]