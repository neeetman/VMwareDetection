#pragma once
typedef std::basic_string<TCHAR> _tstring;

BOOL IsWoW64();
BOOL IsFileExists(const TCHAR* szFilePath);
BOOL IsDirectoryExists(const TCHAR* szPath);
BOOL IsMacAddrExists(const BYTE* szMac);
BOOL IsRegKeyValueExists(HKEY hKey, const TCHAR* szSubkey, const TCHAR* szValueName, _tstring szSearchStr);
BOOL CheckSystemFirmware(DWORD signature, DWORD table, PBYTE szPattern);
DWORD GetProcessIdByName(const TCHAR* szProcName);
BOOL InitWMI(IWbemServices** pSvc, IWbemLocator** pLoc, const TCHAR* szWmiNamespace);
BOOL ExecWMIQuery(IWbemServices** pSvc, IWbemLocator** pLoc, IEnumWbemClassObject** pEnumerator, const TCHAR* szQuery);
int QueryCountWMI(const _TCHAR* query);