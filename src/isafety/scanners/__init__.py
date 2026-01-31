from abc import ABC, abstractmethod
from typing import *


class BackupResultItem(object):
    _data: dict

    def __init__(self, data):
        self._data = data

    @property
    def data(self):
        return self._data


class BackupResultCategory(object):
    _name: str
    _format_string: str
    _results: List[BackupResultItem]

    def __init__(self, name, format_string):
        self._name = name
        self._format_string = format_string
        self._results = []

    def format_item(self, item: BackupResultItem) -> str:
        return self._format_string.format(item.data)

    def add_result(self, result: BackupResultItem):
        self._results.append(result)

    @property
    def title(self):
        return self._name

    @property
    def results(self):
        return self._results


class ScannerBase(ABC):

    def __init__(self, backup):
        self.backup = backup

    @abstractmethod
    def scan(self):
        pass
