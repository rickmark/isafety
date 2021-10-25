import re
from typing import Sequence

SYSCFG_REGEX = re.compile('"AppleDiagnosticDataSysCfg" = <([0-9a-f]*)>')


class SysCfg(object):
    def __init__(self, data):
        pass


def gather_data_from_sysdiagnose(path: str) -> SysCfg:
    with open(path, 'r') as file:
        for line in file.readlines():
            match = SYSCFG_REGEX.search(line)
            if match:
                data = bytes.fromhex(match[1])
                return SysCfg(data)
