from typing import override

from src.isafety.collectors import ProcessCollectorBase


class OctagonTrustCollector(ProcessCollectorBase):
    @override
    def command(self):
        return ["otctl", "status", "--json"]

class CloudKitKeyStorageCollector(ProcessCollectorBase):
    @override
    def command(self):
        return ["ckksctl", "status", "--json"]

