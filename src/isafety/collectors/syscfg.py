import re

from src.isafety import CollectorBase


class SysCfgCollector(CollectorBase):
    SYSCFG_REGEX = re.compile('"AppleDiagnosticDataSysCfg" = <([0-9a-f]*)>')

    def gather_data_from_sysdiagnose(path: str) -> SysCfg:
        with open(path, 'r') as file:
            for line in file.readlines():
                match = SYSCFG_REGEX.search(line)
                if match:
                    data = bytes.fromhex(match[1])
                    return SysCfg(data)
