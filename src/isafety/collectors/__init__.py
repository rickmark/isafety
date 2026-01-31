from abc import abstractmethod, ABC
import functools
from enum import Enum
from typing import override


class CollectionDataType(Enum):
    UNKNOWN = 0
    RAW = 1
    JSON = 2
    XML = 3
    PLIST = 4
    ASN1 = 5
    CMS = 6 # Cryptographic Message Syntax
    SQLITE = 7
    ARCHIVE = 8
    DISK = 9


class CollectorBase(ABC):
    @abstractmethod
    @property
    def type(self) -> CollectionDataType:
        pass

    @functools.cache
    @abstractmethod
    def collect(self):
        pass




class ProcessCollectorBase(CollectorBase):
    @property
    @abstractmethod
    def command(self) -> list[str]:
        pass

    @override
    def collect(self):
        command = self.command
