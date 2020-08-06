from ctypes import *
from platform import system
from typing import *

if "Darwin" in system():
    LIBIBACKUP = cdll.LoadLibrary('libibackup-1.0.dylib')
elif "Linux" in system():
    LIBIBACKUP = cdll.LoadLibrary('libibackup-1.0.so')


LIBIBACKUP.libibackup_preflight_backup.restype = c_bool
LIBIBACKUP.libibackup_preflight_backup.argtypes = [c_char_p]
LIBIBACKUP.libibackup_open_backup.argtypes = [c_char_p, POINTER(c_void_p)]
LIBIBACKUP.libibackup_list_domains.argtypes = [c_void_p, POINTER(POINTER(c_char_p))]
LIBIBACKUP.libibackup_free.argtypes = [c_void_p]


class LocalBackup(object):
    _path: str
    _client: c_void_p

    def __init__(self, path: str):
        if LIBIBACKUP.libibackup_preflight_backup(path.encode('utf-8')):
            self._path = path
            self._client = c_void_p()
            LIBIBACKUP.libibackup_open_backup(path.encode('utf-8'), pointer(self._client))
        else:
            raise RuntimeError

    def domains(self) -> list:
        result = []
        domains = pointer(c_char_p())

        LIBIBACKUP.libibackup_list_domains(self._client, byref(domains))

        index = 0
        domain = domains[index]
        while domain is not None:
            result.append(domain.decode('utf-8'))
            index += 1
            domain = domains[index]

        return result