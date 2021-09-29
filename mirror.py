import os
import subprocess
from ctypes import *
from ctypes.wintypes import *

configFilePath = os.path.join(os.path.dirname(__file__), 'conf', 'config.cfg')

kernel32 = WinDLL('kernel32')
LPDWORD = POINTER(DWORD)
UCHAR = c_ubyte

GetFileAttributesW = kernel32.GetFileAttributesW
GetFileAttributesW.restype = DWORD
GetFileAttributesW.argtypes = (LPCWSTR,)

FILE_ATTRIBUTE_HIDDEN = 2
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT = 0x00400

CreateFileW = kernel32.CreateFileW
CreateFileW.restype = HANDLE
CreateFileW.argtypes = (LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE)

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = (HANDLE,)

INVALID_HANDLE_VALUE = HANDLE(-1).value
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.restype = BOOL
DeviceIoControl.argtypes = (HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID)

FSCTL_GET_REPARSE_POINT = 0x000900A8
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C
MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 0x4000

sortedRootsCache = []
sortedDirData = []


class GENERIC_REPARSE_BUFFER(Structure):
    _fields_ = (('DataBuffer', UCHAR * 1),)


class SYMBOLIC_LINK_REPARSE_BUFFER(Structure):
    _fields_ = (('SubstituteNameOffset', USHORT),
                ('SubstituteNameLength', USHORT),
                ('PrintNameOffset', USHORT),
                ('PrintNameLength', USHORT),
                ('Flags', ULONG),
                ('PathBuffer', WCHAR * 1))

    @property
    def PrintName(self):
        arrayt = WCHAR * (self.PrintNameLength // 2)
        offset = type(self).PathBuffer.offset + self.PrintNameOffset
        return arrayt.from_address(addressof(self) + offset).value


class MOUNT_POINT_REPARSE_BUFFER(Structure):
    _fields_ = (('SubstituteNameOffset', USHORT),
                ('SubstituteNameLength', USHORT),
                ('PrintNameOffset', USHORT),
                ('PrintNameLength', USHORT),
                ('PathBuffer', WCHAR * 1))

    @property
    def PrintName(self):
        arrayt = WCHAR * (self.PrintNameLength // 2)
        offset = type(self).PathBuffer.offset + self.PrintNameOffset
        return arrayt.from_address(addressof(self) + offset).value


class REPARSE_DATA_BUFFER(Structure):
    class REPARSE_BUFFER(Union):
        _fields_ = (('SymbolicLinkReparseBuffer', SYMBOLIC_LINK_REPARSE_BUFFER),
                    ('MountPointReparseBuffer', MOUNT_POINT_REPARSE_BUFFER),
                    ('GenericReparseBuffer', GENERIC_REPARSE_BUFFER))

    _fields_ = (('ReparseTag', ULONG),
                ('ReparseDataLength', USHORT),
                ('Reserved', USHORT),
                ('ReparseBuffer', REPARSE_BUFFER))

    _anonymous_ = ('ReparseBuffer',)


def get_sorted_root_data(root):
    if root == sampleDir:
        return [targetDir, 0]
    if sortedRootsCache:
        for rootVals in sortedRootsCache:
            if root == rootVals[0]:
                return [rootVals[1], rootVals[2]]
    if root[0:len(sampleDir)] == sampleDir:
        return [targetDir + root[len(sampleDir):len(root)], 0]
    return [root, 0]


def is_to_be_walked(path):
    if path == sampleDir:
        return True
    for dirToWalk in dirsToWalk:
        pathToWalk = os.path.join(sampleDir, dirToWalk)
        if pathToWalk == path[0:len(pathToWalk)]:
            return True
    return False


def is_hidden(path):
    attribs = GetFileAttributesW(path)
    hidden = attribs & FILE_ATTRIBUTE_HIDDEN
    return hidden


def is_custom_dir(path):
    fullPath = os.path.join(path, '')
    dir = os.path.split(os.path.dirname(fullPath))[1]
    for customDir in customDirs:
        if dir == customDir:
            return True
    return False


def is_final_dir(path):
    for root, dirs, files in os.walk(path):
        if dirs and dirs != ['More']:
            return False
        else:
            return True


def is_junction(path):
    result = GetFileAttributesW(path)
    if result == INVALID_FILE_ATTRIBUTES:
        raise WinError()
    return bool(result & FILE_ATTRIBUTE_REPARSE_POINT)


def read_junction(path):
    reparse_point_handle = CreateFileW(path, 0, 0, None, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, None)
    if reparse_point_handle == INVALID_HANDLE_VALUE:
        raise WinError()
    target_buffer = c_buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
    n_bytes_returned = DWORD()
    io_result = DeviceIoControl(reparse_point_handle, FSCTL_GET_REPARSE_POINT, None, 0, target_buffer, len(target_buffer), byref(n_bytes_returned), None)
    CloseHandle(reparse_point_handle)
    if not io_result:
        raise WinError()
    rdb = REPARSE_DATA_BUFFER.from_buffer(target_buffer)
    if rdb.ReparseTag == IO_REPARSE_TAG_SYMLINK:
        return rdb.SymbolicLinkReparseBuffer.PrintName
    elif rdb.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT:
        return rdb.MountPointReparseBuffer.PrintName
    raise ValueError("not a link")


def parse_dir(origRoot, origDirs):
    if not is_final_dir(origRoot):
        sortedRootData = get_sorted_root_data(origRoot)
        sortedDirs = []
        for origDir in origDirs:
            origPath = os.path.join(origRoot, origDir)
            if is_to_be_walked(origPath):
                if sortedRootData[1] == 1 or is_hidden(origPath):
                    sortedRootsCache.append([origPath, '', 1])
                else:
                    if sortedRootData[1] == 2:
                        sortedRootsCache.append([origPath, '', 2])
                    else:
                        print('Reading path "' + origPath + '"')
                        sortedDirs.append([origPath, origDir])

        if sortedDirs:

            # start of actual sorting jazz

            sortedByGroups = [[]]
            groupParam = 'SortGroup='
            for sortedVals in sortedDirs:
                fileName = os.path.join(origRoot, sortedVals[1] + '.nfo')
                groupNum = False;
                if os.path.isfile(fileName):
                    file = open(fileName, 'r')
                    lines = file.readlines()
                    for line in lines:
                        if line[0:len(groupParam)] == groupParam:
                            groupNumTmp = line[len(groupParam):len(line)]
                            groupNum = groupNumTmp.strip()
                            break
                if groupNum and groupNum.isnumeric():
                    if int(groupNum) >= len(sortedByGroups):
                        for x in range(len(sortedByGroups), int(groupNum) + 1):
                            sortedByGroups.insert(x, [])
                    subArr = sortedByGroups[int(groupNum)]
                    subArr.append(sortedVals)
                    sortedByGroups[int(groupNum)] = subArr
                    continue
                subArr = sortedByGroups[0]
                subArr.append(sortedVals)
                sortedByGroups[0] = subArr
            sortedDirs = []
            y = len(sortedByGroups) - 1
            while y >= 0:
                subArr = sortedByGroups[y]
                if (len(subArr) > 0):
                    for subArrVals in subArr:
                        sortedDirs.append(subArrVals)
                y -= 1

            # end of sorting jazz

            sortIndex = 1
            for sortedVals in sortedDirs:
                sortedDigits = '{0:0=2d}'.format(sortIndex)
                sortedDir = '[' + sortedDigits + '] ' + sortedVals[1]
                sortedPath = os.path.join(sortedRootData[0], sortedDir)
                if is_junction(sortedVals[0]):
                    sortedRootsCache.append([sortedVals[0], sortedPath, 2])
                    junctionTarget = read_junction(sortedVals[0])
                    if is_final_dir(sortedVals[0]):
                        sortedDirData.append([sortedRootData[0], sortedDir, junctionTarget])
                    else:
                        sortedDirData.append([sortedRootData[0], sortedDir, junctionTarget, True])
                else:
                    if is_custom_dir(sortedVals[0]):
                        sortedRootsCache.append([sortedVals[0], sortedPath, 2])
                        sortedDirData.append([sortedRootData[0], sortedDir, sortedVals[0]])
                    else:
                        sortedRootsCache.append([sortedVals[0], sortedPath, 0])
                        if is_final_dir(sortedVals[0]):
                            sortedDirData.append([sortedRootData[0], sortedDir, sortedVals[0]])
                        else:
                            sortedDirData.append([sortedRootData[0], sortedDir])

                sortIndex += 1


def value_found(line, valParam):
    if line[0:len(valParam)] == valParam:
        value = line[len(valParam):len(line)]
        if value.startswith('"') and value.endswith('"'):
            return value[1:len(value) - 1]

        if value.startswith('[') and value.endswith(']'):
            splitValues = value[1:len(value) - 1].split(',')
            result = []
            for splitValue in splitValues:
                splitTmp = splitValue.strip()
                if splitTmp.startswith('"') and splitTmp.endswith('"'):
                    result.append(splitTmp[1:len(splitTmp) - 1])
            return result

    return False


sampleDir = False
targetDir = False
dirsToWalk = False
customDirs = False
configData = False


# read config data

if os.path.isfile(configFilePath):
    file = open(configFilePath, 'r')
    lines = file.readlines()
    for line in lines:
        strippedLine = line.strip()

        if value_found(strippedLine, 'SourceFolder='):
            sampleDir = value_found(strippedLine, 'SourceFolder=')
            if not os.path.isdir(sampleDir):
                print('Source directory not found at "' + sampleDir + '".')
                sampleDir = False

        if value_found(strippedLine, 'SubFolders='):
            dirsToWalk = value_found(strippedLine, 'SubFolders=')

        if value_found(strippedLine, 'MixedFolders='):
            customDirs = value_found(strippedLine, 'MixedFolders=')

        if value_found(strippedLine, 'PathToTarget='):
            pathToTarget = value_found(strippedLine, 'PathToTarget=')
            targetDir = os.path.join(os.path.dirname(configFilePath), pathToTarget)
            if not os.path.isdir(targetDir):
                print('Target directory not found at "' + targetDir + '".')
                targetDir = False

    if sampleDir and dirsToWalk and customDirs and targetDir:
        configData = True

else:
    print('Config file missing at "' + configFilePath + '".')


if configData:

    # collect latest structure data

    parse_dir(sampleDir, dirsToWalk)
    for dirToWalk in dirsToWalk:
        for walkRoot, walkDirs, walkFiles in os.walk(os.path.join(sampleDir, dirToWalk)):
            parse_dir(walkRoot, walkDirs)

    for dirData in sortedDirData:
        if len(dirData) >= 4:
            sortedRootData = get_sorted_root_data(dirData[2])
            dirData[2] = sortedRootData[0]

    # clear existing mirror structure

    existingDirs = os.listdir(targetDir)
    for existingDir in existingDirs:
        dirBase = existingDir.split()[0]
        if dirBase.startswith('[') and dirBase.endswith(']'):
            if str(dirBase[1:len(dirBase) - 1].isnumeric()):
                target = os.path.join(targetDir, existingDir)
                command = 'rmdir /q /s "' + target + '"'
                with open(os.devnull, 'wb') as devnull:
                    subprocess.check_call(command, stdout=devnull, stderr=subprocess.STDOUT, shell=True)
                print('Delete directory "' + existingDir + '" at "' + targetDir + '"')

    # write sorted mirror structure

    for dirData in sortedDirData:
        if len(dirData) >= 3:
            source = os.path.join(dirData[0], dirData[1])
            target = dirData[2]
            command = 'mklink /j "' + source + '" "' + target + '"'
            with open(os.devnull, 'wb') as devnull:
                subprocess.check_call(command, stdout=devnull, stderr=subprocess.STDOUT, shell=True)
            print('Adding junction "' + dirData[1] + '" at "' + dirData[0] + '" pointing to "' + target + '"')
        else:
            try:
                os.mkdir(os.path.join(dirData[0], dirData[1]))
            except OSError:
                print('Failed adding directory "' + dirData[1] + '" at "' + dirData[0] + '"')
            else:
                print('Adding directory "' + dirData[1] + '" at "' + dirData[0] + '"')

    print('Done.')

else:
    print('Config data missing or incorrect.')
