#include "pch.h"
#include "Utils.h"


BOOL IsWoW64()
{
	BOOL isWow64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &isWow64);
	return isWow64;
}

BOOL IsFileExists(const TCHAR* szFilePath)
{
	DWORD dwAttrib = GetFileAttributes(szFilePath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

BOOL IsDirectoryExists(const TCHAR* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

BOOL IsMacAddrExists(const BYTE* szMac)
{
	ULONG bufferSize = 0;
	// AdapterAddresses = NULL, only the outBufLen buffer size is obtained
	DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, NULL, &bufferSize);
	if (dwRetVal != ERROR_BUFFER_OVERFLOW) {
		PrintLastError(_T("GetAdaptersAddresses"));
		return FALSE;
	}
		
	PIP_ADAPTER_ADDRESSES pAdapterAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
	if (pAdapterAddresses == nullptr) {
		PrintLastError(_T("IsMacAddrExists malloc"));
		return FALSE;
	}

	dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapterAddresses, &bufferSize);
	if (dwRetVal != NO_ERROR) {
		PrintLastError(_T("GetAdaptersAddresses"));
		free(pAdapterAddresses);
		return FALSE;
	}

	PIP_ADAPTER_ADDRESSES pCurAdapter = pAdapterAddresses;
	while (pCurAdapter) {
		if (pCurAdapter->PhysicalAddressLength == 6 && memcmp(pCurAdapter->PhysicalAddress, szMac, 3) == 0) {
			free(pAdapterAddresses);
			return TRUE;
		}
		pCurAdapter = pCurAdapter->Next;
	}

	return FALSE;
}

BOOL IsRegKeyValueExists(HKEY hKey, const TCHAR* szSubkey, const TCHAR* szValueName, _tstring szSearchStr)
{
	HKEY  hkResult = NULL;
	TCHAR lpData[1024] = { 0 };
	DWORD dwDataSize = MAX_PATH;

	if (RegOpenKeyEx(hKey, szSubkey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hkResult, szValueName, NULL, NULL, (LPBYTE)lpData, &dwDataSize) == ERROR_SUCCESS)
		{
			_tstring value = _tstring(lpData, dwDataSize);

			auto it = std::search(value.begin(), value.end(), szSearchStr.begin(), szSearchStr.end(),
				[](TCHAR c1, TCHAR c2) { return std::tolower(c1) == std::tolower(c2); });

			if (it != value.end()) {
				RegCloseKey(hkResult);
				return TRUE;
			}
		}
		RegCloseKey(hkResult);
	}
	return FALSE;
}

BOOL CheckSystemFirmware(DWORD signature, DWORD table, PBYTE szPattern)
{
	// Get SMBIOS table size
	DWORD dwSize = GetSystemFirmwareTable(signature, table, NULL, 0);
	if (dwSize == 0) {
		PrintLastError(_T("GetSystemFirmwareTable with pBuffer=NULL"));
		return FALSE;
	}


	LPBYTE firmwareTable = static_cast<PBYTE>(malloc(dwSize));
	if (firmwareTable == nullptr) {
		PrintLastError(_T("CheckSystemFirmware malloc"));
		return FALSE;
	}

	SecureZeroMemory(firmwareTable, dwSize);

	DWORD resultSize = GetSystemFirmwareTable(signature, table, firmwareTable, dwSize);
	if (resultSize == 0) {
		PrintLastError(_T("GetSystemFirmwareTable"));
		free(firmwareTable);
		return FALSE;
	}

	DWORD patternSize = strnlen((const char*)szPattern, MAX_PATH);
	BYTE* result = std::search(firmwareTable, firmwareTable + dwSize, szPattern, szPattern + patternSize);
	
	free(firmwareTable);
	return result != firmwareTable + dwSize;
}

DWORD GetProcessIdByName(const TCHAR* szProcName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		PrintLastError(_T("CreateToolhelp32Snapshot"));
		return 0;
	}


	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);

	BOOL bRet = Process32First(hSnap, &pe32);
	while (bRet) {
		if (!StrCmpI(pe32.szExeFile, szProcName))
			break;

		bRet = Process32Next(hSnap, &pe32);
	}

	CloseHandle(hSnap);

	return bRet? pe32.th32ProcessID : 0;
}

BOOL InitWMI(IWbemServices** pSvc, IWbemLocator** pLoc, const TCHAR* szWmiNamespace)
{
	// Initialize COM.
	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		PrintLastError(_T("CoInitializeEx"));
		return 0;
	}

	// Set general COM security levels
	hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hres)) {
		PrintLastError(_T("CoInitializeSecurity"));
		CoUninitialize();
		return 0;
	}

	// Obtain the initial locator to WMI (CLSID_WbemLocator indicate WMI interface)
	hres = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(pLoc));
	if (FAILED(hres)) {
		PrintLastError(_T("CoCreateInstance"));
		CoUninitialize();
		return 0;
	}

	//Connect to WMI through the IWbemLocator::ConnectServer method
	hres = (*pLoc)->ConnectServer(
		_bstr_t(szWmiNamespace), // WMI namespace
		NULL, // 用户名
		NULL, // 密码
		NULL, // 本地连接
		WBEM_FLAG_CONNECT_USE_MAX_WAIT, // 安全标志
		0, // 授权级别
		0, // 认证级别
		pSvc
	);
	if (FAILED(hres)) {
		PrintLastError(_T("ConnectServer"));
		(*pLoc)->Release();
		CoUninitialize();
		return 0;
	}

	// Set security levels on the proxy. Local call COM also use RPC.
	hres = CoSetProxyBlanket(
		*pSvc, // 接口指针
		RPC_C_AUTHN_WINNT, // 认证服务
		RPC_C_AUTHZ_NONE, // 授权服务
		NULL, // 服务器
		RPC_C_AUTHN_LEVEL_CALL, // 认证级别
		RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation 级别
		NULL, // 授权信息
		EOAC_NONE // Capabilities
	);
	if (FAILED(hres))
	{
		PrintLastError(_T("CoSetProxyBlanket"));
		(*pSvc)->Release();
		(*pLoc)->Release();
		CoUninitialize();
		return 0;
	}

	return 1;
}

BOOL ExecWMIQuery(IWbemServices** pSvc, IWbemLocator** pLoc, IEnumWbemClassObject** pEnumerator, const TCHAR* szQuery)
{
	BOOL bQueryResult = TRUE;

	HRESULT hres = (*pSvc)->ExecQuery(
		bstr_t("WQL"),
		bstr_t(szQuery),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL, 
		pEnumerator
	);
	if (FAILED(hres)) {
		bQueryResult = FALSE;
		PrintLastError(_T("ExecQuery"));
		(*pSvc)->Release();
		(*pLoc)->Release();
		CoUninitialize();
	}

	return bQueryResult;
}

int QueryCountWMI(const _TCHAR* query)
{
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	HRESULT hRes;
	int count = 0;

	// Init WMI
	if (!InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2")))
		return -1;

	// If success, execute the desired query
	if (!ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_Fan"))) {
		pSvc->Release();
		pLoc->Release();
		return -1;
	}

	// Get the data from the query
	IWbemClassObject* pclsObj = NULL;
	ULONG uRet = 0;

	while (pEnumerator)
	{
		hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uRet);
		if (uRet == 0)
			break;

		count++;
		pclsObj->Release();
	}

	// Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return count;
}