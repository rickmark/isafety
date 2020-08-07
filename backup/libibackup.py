from ctypes import *
from platform import system
from typing import *
from enum import *

if "Darwin" in system():
    LIBIBACKUP = cdll.LoadLibrary('libibackup-1.0.dylib')
elif "Linux" in system():
    LIBIBACKUP = cdll.LoadLibrary('libibackup-1.0.so')


class BackupItemType(Enum):
    FILE = 1
    DIRECTORY = 2
    SYMBOLIC_LINK = 4


class BackupFileEntry(Structure):
    _fields_ = [("file_id", c_char_p),
                ("domain", c_char_p),
                ("relative_path", c_char_p),
                ("target", c_char_p),
                ("type", c_int32)]

LIBIBACKUP.libibackup_preflight_backup.restype = c_bool
LIBIBACKUP.libibackup_preflight_backup.argtypes = [c_char_p]
LIBIBACKUP.libibackup_open_backup.argtypes = [c_char_p, POINTER(c_void_p)]
LIBIBACKUP.libibackup_list_domains.argtypes = [c_void_p, POINTER(POINTER(c_char_p))]
LIBIBACKUP.libibackup_list_files_for_domain.argtypes = [c_void_p, c_char_p, POINTER(POINTER(POINTER(BackupFileEntry)))]
LIBIBACKUP.libibackup_free.argtypes = [c_void_p]
LIBIBACKUP.libibackup_get_path_for_file_id.restype = c_char_p
LIBIBACKUP.libibackup_get_path_for_file_id.argtypes = [c_void_p, c_char_p]


class FileMetadata(object):
    pass


class FileEntry(object):
    _file_id: str
    _relative_path: Optional[str]
    _domain: str
    _type: BackupItemType
    _target: Optional[str]
    _metadata: Optional[FileMetadata]

    def __init__(self, file_entry: BackupFileEntry):
        self._file_id = file_entry.file_id.decode('utf-8')
        self._relative_path = file_entry.relative_path.decode('utf-8')
        self._domain = file_entry.domain.decode('utf-8')
        self._type = BackupItemType(file_entry.type)


    @property
    def file_id(self) -> str:
        return self._file_id

    @property
    def relative_path(self) -> str:
        return self._relative_path


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

    def files_in_domain(self, domain: str) -> list:
        result = []
        files = pointer(pointer(BackupFileEntry()))

        LIBIBACKUP.libibackup_list_files_for_domain(self._client, domain.encode('utf-8'), byref(files))

        index = 0
        file = files[index]
        while file:
            result.append(FileEntry(file.contents))
            index += 1
            file = files[index]

        return result

    def get_path_by_id(self, file_id: str) -> str:
        file_id_string = create_string_buffer(file_id.encode('utf-8'))
        return LIBIBACKUP.libibackup_get_path_for_file_id(self._client, file_id_string).decode('utf-8')