#include "pch.h"

#include "VMwareDetection.h"


void CheckVmwareFiles()
{
	// Array of strings of blacklisted paths
	const TCHAR* szPaths[] = {
		_T("System32\\vm3dc003.dll"),
		_T("System32\\vm3ddevapi64-debug.dll"),
		_T("System32\\vm3ddevapi64-release.dll"),
		_T("System32\\vm3ddevapi64-stats.dll"),
		_T("System32\\vm3ddevapi64.dll"),
		_T("System32\\vm3dgl64.dll"),
		_T("System32\\vm3dglhelper64.dll"),
		_T("System32\\vm3dservice.exe"),
		_T("System32\\vm3dum64-debug.dll"),
		_T("System32\\vm3dum64-stats.dll"),
		_T("System32\\vm3dum64.dll"),
		_T("System32\\vm3dum64_10-debug.dll"),
		_T("System32\\vm3dum64_10-stats.dll"),
		_T("System32\\vm3dum64_10.dll"),
		_T("System32\\vm3dum64_loader.dll"),
		_T("System32\\vmGuestLib.dll"),
		_T("System32\\vmGuestLibJava.dll"),
		_T("System32\\vmhgfs.dll"),
		_T("System32\\VMWSU.DLL"),
		_T("System32\\vsocklib.dll"),
		_T("System32\\drivers\\vm3dmp.sys"),
		_T("System32\\drivers\\vm3dmp_loader.sys"),
		_T("System32\\drivers\\vm3dmp-debug.sys"),
		_T("System32\\drivers\\vm3dmp-stats.sys"),
		_T("System32\\drivers\\vmnet.sys"),
		_T("System32\\drivers\\vmmouse.sys"),
		_T("System32\\drivers\\vmusb.sys"),
		_T("System32\\drivers\\vmci.sys"),
		_T("System32\\drivers\\vmhgfs.sys"),
		_T("System32\\drivers\\vmmemctl.sys"),
		_T("System32\\drivers\\vmx86.sys"),
		_T("System32\\drivers\\vmrawdsk.sys"),
		_T("System32\\drivers\\vmusbmouse.sys"),
		_T("System32\\drivers\\vmkdb.sys"),
		_T("System32\\drivers\\vmnetuserif.sys"),
		_T("System32\\drivers\\vmnetadapter.sys"),
	};

	// Getting Windows Directory
	WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
	TCHAR szWinDir[MAX_PATH] = _T("");
	TCHAR szFullPath[MAX_PATH] = _T("");
	PVOID oldValue = NULL;
	GetWindowsDirectory(szWinDir, MAX_PATH);

	// Access to files under System32 is redirected to SysWOW64
	if (IsWoW64()) {
		Wow64DisableWow64FsRedirection(&oldValue);
	}

	std::vector<_tstring> detectedPaths;
	for (const TCHAR* szPath : szPaths)
	{
		PathCombine(szFullPath, szWinDir, szPath);

		if (IsFileExists(szFullPath)) {
			detectedPaths.push_back(_tstring(_T("Detected file ")) + szFullPath);
		}
	}

	if (IsWoW64()) {
		Wow64RevertWow64FsRedirection(&oldValue);
	}

	const TCHAR* szVMwarePath = _T("C:\\Program Files\\VMware\\");
	if (IsDirectoryExists(szVMwarePath)) {
		detectedPaths.push_back(_T("Detected directory C:\\Program Files\\VMware\\"));
	}

	if (!detectedPaths.empty()) {
		PrintResult(TRUE, _T("Checking potential files and directories"));
		for (const _tstring file : detectedPaths) {
			PrintSubCheckText(file.c_str());
		}
	}
	else {
		PrintResult(FALSE, _T("Checking potential files and directories"));
	}

}

void CheckVmwareDevices()
{
	const TCHAR* devices[] = {
		_T("\\\\.\\HGFS"),
		_T("\\\\.\\vmci"),
	};

	std::vector<_tstring> detectedDevices;
	for (const TCHAR* device : devices)
	{
		HANDLE hFile = CreateFile(device, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking device %s "), device);

		if (hFile != INVALID_HANDLE_VALUE) {
			CloseHandle(hFile);
			detectedDevices.push_back(_tstring(_T("Detected device ")) + device);
		}
	}

	if (!detectedDevices.empty()) {
		PrintResult(TRUE, _T("Checking devices"));
		for (const _tstring file : detectedDevices) {
			PrintSubCheckText(file.c_str());
		}
	}
	else {
		PrintResult(FALSE, _T("Checking devices"));
	}
}

void CheckVmwareMac()
{
	const BYTE* szMacs[] = {
		(BYTE*)"\x00\x05\x69",
		(BYTE*)"\x00\x0C\x29",
		(BYTE*)"\x00\x1C\x14",
		(BYTE*)"\x00\x50\x56"
	};

	std::vector<_tstring> detectedMACs;
	for (const BYTE* mac : szMacs)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking MAC starting with %02X:%02X:%02X"), mac[0], mac[1], mac[2]);
		if (IsMacAddrExists(mac))
			PrintResult(TRUE, msg);
		//else
		//	PrintResult(FALSE, msg);
	}
}

void CheckVmwareReg()
{
	/* Array of strings of blacklisted registry key values */
	const TCHAR* szEntries[][3] = {
		{ _T("HARDWARE\\DESCRIPTION\\System"), _T("SystemBiosVersion"), _T("VMWARE") },
		{ _T("HARDWARE\\DESCRIPTION\\System\\BIOS"), _T("BIOSVendor"), _T("VMWARE") },
		{ _T("HARDWARE\\DESCRIPTION\\System\\BIOS"), _T("BIOSVersion"), _T("VM") },
		{ _T("HARDWARE\\DESCRIPTION\\System\\BIOS"), _T("SystemManufacturer"), _T("VMWARE") },
		{ _T("HARDWARE\\DESCRIPTION\\System\\BIOS"), _T("SystemProductName"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("SYSTEM\\ControlSet001\\Control\\SystemInformation"), _T("SystemManufacturer"), _T("VMWARE") },
		{ _T("SYSTEM\\ControlSet001\\Control\\SystemInformation"), _T("SystemProductName"), _T("VMWARE") },
		{ _T("SYSTEM\\ControlSet001\\Control\\SystemInformation"), _T("BIOSVersion"), _T("VM") },
	};

	WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

	std::vector<_tstring> detectedRegKey;
	for (int i = 0; i < dwLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Detected reg key %s value name %s"), szEntries[i][0], szEntries[i][1]);
		if (IsRegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2])) {
			detectedRegKey.push_back(msg);
		}
	}

	if (!detectedRegKey.empty()) {
		PrintResult(TRUE, _T("Checking the registry"));
		for (const _tstring entry : detectedRegKey) {
			PrintSubCheckText(entry.c_str());
		}
	}
	else {
		PrintResult(FALSE, _T("Checking the registry"));
	}
}

void CheckVmwareSMBIOS()
{
	if (CheckSystemFirmware(static_cast<DWORD>('RSMB'), 0x0000, (PBYTE)"VMware"))
		PrintResult(TRUE, _T("Checking SMBIOS firmware"));
	else 
		PrintResult(FALSE, _T("Checking SMBIOS firmware"));
}

void CheckVmwareACPI()
{
	DWORD bufferSize = EnumSystemFirmwareTables(static_cast<DWORD>('ACPI'), NULL, 0);
	if (bufferSize == 0) {
		PrintLastError(_T("EnumSystemFirmwareTables with pBuffer=null"));
		return;
	}

	PDWORD tableNames = static_cast<PDWORD>(malloc(bufferSize));
	if (tableNames == nullptr) {
		PrintLastError(_T("CheckVmwareACPI malloc"));
		return;
	}
		
	SecureZeroMemory(tableNames, bufferSize);

	if (EnumSystemFirmwareTables(static_cast<DWORD>('ACPI'), tableNames, bufferSize) == 0) {
		PrintLastError(_T("EnumSystemFirmwareTables"));
		free(tableNames);
		return;
	}

	DWORD tableCount = bufferSize / sizeof(DWORD);
	if (tableCount > 0) {
		for (DWORD i = 0; i < tableCount; i++) {
			TCHAR msg[256] = _T("");
			_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking ACPI firmware table #%d "), i);

			if (CheckSystemFirmware(static_cast<DWORD>('ACPI'), tableNames[i], (PBYTE)"VMWARE"))
				PrintResult(TRUE, msg);
			else
				PrintResult(FALSE, msg);
		}
	}	
}

void CheckVmwareProcesses()
{
	const TCHAR* szProcesses[] = {
		_T("vmtoolsd.exe"),
		_T("vmwaretray.exe"),
		_T("vmwareuser.exe"),
		_T("VGAuthService.exe"),
		_T("vmacthlp.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking VWware process %s "), szProcesses[i]);
		if (GetProcessIdByName(szProcesses[i]))
			PrintResult(TRUE, msg);
		else
			PrintResult(FALSE, msg);
	}
}

void CheckDiskdrive()
{
	// Create a HDEVINFO with all present diskdrive devices.
	HDEVINFO hDevInfo = SetupDiGetClassDevs((LPGUID)&GUID_DEVCLASS_DISKDRIVE, NULL, NULL, DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE) {
		PrintLastError(_T("SetupDiGetClassDevs"));
		return;
	}
		
	SP_DEVINFO_DATA deviceInfoData = { 0 };
	deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	/* Init some vars */
	DWORD dwPropertyRegDataType;
	LPTSTR buffer = NULL;
	DWORD dwSize = 0;

	// Enumerate through all devices in the HDEVINFO.
	for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &deviceInfoData); i++)
	{
		// Get the hardware ID of the device
		while (!SetupDiGetDeviceRegistryProperty(hDevInfo, &deviceInfoData, SPDRP_HARDWAREID,
			&dwPropertyRegDataType, (PBYTE)buffer, dwSize, &dwSize))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				if (buffer)
					LocalFree(buffer);
				// Double the size to avoid problems on 
				// W2k MBCS systems per KB 888609. 
				buffer = (LPTSTR)LocalAlloc(LPTR, dwSize * 2);
				if (buffer == NULL)
					break;
			}
			else
				break;
		}

		TCHAR msg[256] = _T("");

		if (buffer == NULL)
			continue;

		// Double the size before, here p wont out of bounds
		for (LPTSTR p = buffer; *p; p += _tcslen(p) + 1) {
			_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking diskdrive hardware ID %s"), p);
			PrintResult((StrStrI(p, _T("vmware")) != NULL), msg);
		}
	}

	if (buffer)
		LocalFree(buffer);

	SetupDiDestroyDeviceInfoList(hDevInfo);
}

void CheckCPUID()
{
	INT CPUInfo[4] = { -1 };
	CHAR szHypervisorVendor[0x40];

	// Query hypervisor precense using CPUID (EAX=1), BIT 31 in ECX
	__cpuid(CPUInfo, 1);
	if ((CPUInfo[2] >> 31) & 1)
		PrintResult(TRUE, _T("Checking if CPU hypervisor field is set using cpuid(0x1)"));
	else
		PrintResult(FALSE, _T("Checking if CPU hypervisor field is set using cpuid(0x1)"));

	// When CPUID is called with EAX = 0x40000000, cpuid return the hypervisor signature.
	__cpuid(CPUInfo, 0x40000000);
	SecureZeroMemory(szHypervisorVendor, sizeof(szHypervisorVendor));
	memcpy(szHypervisorVendor, CPUInfo + 1, 12);

	if (_strcmpi(szHypervisorVendor, "VMwareVMware") == 0) 
		PrintResult(TRUE, _T("Checking hypervisor vendor using cpuid(0x40000000)"));
	else
		PrintResult(FALSE, _T("Checking hypervisor vendor using cpuid(0x40000000)"));
}

void CheckBIOSSerialNumberWMI()
{
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bFound = FALSE;
	HRESULT hRes;

	// Init WMI
	if (!InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2")))
		return;

	// If success, execute the desired query
	if (!ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_BIOS")))
		return;

	// Get the data from the query
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	VARIANT vtProp;

	while (pEnumerator)
	{
		hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
			break;

		// Get the value of the Name property
		VariantInit(&vtProp);
		hRes = pclsObj->Get(_T("SerialNumber"), 0, &vtProp, 0, 0);
		if (SUCCEEDED(hRes)) {
			if (vtProp.vt == VT_BSTR) {
				if (StrStrI(vtProp.bstrVal, _T("VMWare")) != 0)
				{
					bFound = TRUE;
					VariantClear(&vtProp);
					pclsObj->Release();
					break;
				}
			}
			VariantClear(&vtProp);
		}

		// release the current result object
		pclsObj->Release();
	}

	// Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	PrintResult(bFound, _T("Checking SerialNumber from BIOS using WMI"));
}

void CheckModelComputerSystemWMI()
{
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bFound = FALSE;
	HRESULT hRes;

	// Init WMI
	if (!InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2")))
		return;

	// If success, execute the desired query
	if (!ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_ComputerSystem")))
		return;

	// Get the data from the query
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	VARIANT vtProp;

	while (pEnumerator)
	{
		hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
			break;

		// Get the value of the Name property
		VariantInit(&vtProp);
		hRes = pclsObj->Get(_T("Model"), 0, &vtProp, 0, 0);
		if (SUCCEEDED(hRes)) {
			if (vtProp.vt == VT_BSTR) {
				if (StrStrI(vtProp.bstrVal, _T("VMWare")) != 0) {
					VariantClear(&vtProp);
					pclsObj->Release();
					bFound = TRUE;
					break;
				}
			}
			VariantClear(&vtProp);
		}

		// release the current result object
		pclsObj->Release();
	}

	// Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	PrintResult(bFound, _T("Checking Model from ComputerSystem using WMI"));
}

void CheckManufacturerComputerSystemWMI()
{
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bFound = FALSE;
	HRESULT hRes;

	// Init WMI
	if (!InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2")))
		return;

	// If success, execute the desired query
	if (!ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_ComputerSystem")))
		return;

	// Get the data from the query
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	VARIANT vtProp;

	while (pEnumerator)
	{
		hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
			break;

		// Get the value of the Name property
		VariantInit(&vtProp);
		hRes = pclsObj->Get(_T("Manufacturer"), 0, &vtProp, 0, 0);
		if (SUCCEEDED(hRes)) {
			if (vtProp.vt == VT_BSTR) {
				if (StrStrI(vtProp.bstrVal, _T("VMWare")) != 0) {
					VariantClear(&vtProp);
					pclsObj->Release();
					bFound = TRUE;
					break;
				}
			}
			VariantClear(&vtProp);
		}

		// release the current result object
		pclsObj->Release();
	}

	// Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	PrintResult(bFound, _T("Checking Manufacturer from ComputerSystem using WMI"));
}

void CheckCPUFanWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM Win32_Fan"));
	PrintResult(count == 0, _T("Checking CPU fan using WMI"));
}

void CheckChacheMemoryWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM Win32_CacheMemory"));
	PrintResult(count == 0, _T("Checking Win32_CacheMemory with WMI"));
}

void CheckVoltageProbeWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM Win32_VoltageProbe"));
	PrintResult(count == 0, _T("Checking Win32_VoltageProbe with WMI"));
}

void CheckThermalZoneInfoWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation"));
	PrintResult(count == 0, _T("Checking ThermalZoneInfo performance counters with WMI"));
}

void CheckCIMMemoryWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM CIM_Memory"));
	PrintResult(count == 0, _T("Checking CIM_Memory with WMI"));
}

void CheckCIMSensorWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM CIM_Sensor"));
	PrintResult(count == 0, _T("Checking CIM_Sensor with WMI"));
}

void CheckCIMNumericSensorWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM CIM_NumericSensor"));
	PrintResult(count == 0, _T("Checking CIM_NumericSensor with WMI"));
}

void CheckCIMTemperatureSensorWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM CIM_TemperatureSensor"));
	PrintResult(count == 0, _T("Checking CIM_TemperatureSensor with WMI"));
}

void CheckCIMVoltageSensorWMI()
{
	int count = QueryCountWMI(_T("SELECT * FROM CIM_VoltageSensor"));
	PrintResult(count == 0, _T("Checking CIM_VoltageSensor with WMI"));
}

void CheckRegServicesDiskEnum()
{
	HKEY hkResult = NULL;
	const TCHAR* diskEnumKey = _T("System\\CurrentControlSet\\Services\\Disk\\Enum");
	DWORD diskCount = 0;
	DWORD cbData = sizeof(diskCount);
	const TCHAR* szChecks[] = {
		_T("vmware"),
		_T("VMW"),
		_T("Virtual"),
	};
	WORD dwChecksLength = sizeof(szChecks) / sizeof(szChecks[0]);
	BOOL bFound = FALSE;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, diskEnumKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS) {
		if (RegQueryValueEx(hkResult, _T("Count"), NULL, NULL, (LPBYTE)&diskCount, &cbData) != ERROR_SUCCESS) {
			RegCloseKey(hkResult);
			return;
		}
		RegCloseKey(hkResult);
	}

	for (unsigned int i = 0; i < diskCount; i++) {
		TCHAR subkey[11];

		_stprintf_s(subkey, sizeof(subkey) / sizeof(subkey[0]), _T("%d"), i);

		for (unsigned int j = 0; j < dwChecksLength; j++) {
			if (IsRegKeyValueExists(HKEY_LOCAL_MACHINE, diskEnumKey, subkey, szChecks[j])) {
				TCHAR msg[256] = _T("");
				_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key %s value name %s"), diskEnumKey, subkey);
				PrintResult(TRUE, msg);
				break;
			}
		}
	}
}

void CheckRegDiskEnum()
{
	HKEY hKey = NULL;
	const TCHAR* szEntries[] = {
		_T("System\\CurrentControlSet\\Enum\\IDE"),
		_T("System\\CurrentControlSet\\Enum\\SCSI"),
	};
	const TCHAR* szChecks[] = {
		_T("vmware"),
		_T("VMW"),
		_T("Virtual"),

	};
	WORD dwEntriesLength = sizeof(szEntries) / sizeof(szEntries[0]);
	WORD dwChecksLength = sizeof(szChecks) / sizeof(szChecks[0]);

	for (unsigned int i = 0; i < dwEntriesLength; i++) {
		DWORD numSubkey = 0;
		DWORD maxSubkeyLen = 0;
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szEntries[i], NULL, KEY_READ, &hKey) != ERROR_SUCCESS) {
			continue;
		}

		if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &numSubkey, &maxSubkeyLen, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
			RegCloseKey(hKey);
			continue;
		}

		DWORD subKeyBufferLen = (maxSubkeyLen + 1) * sizeof(TCHAR);
		TCHAR* subKeyBuffer = (TCHAR*)malloc(subKeyBufferLen);
		if (!subKeyBuffer) {
			RegCloseKey(hKey);
			continue;
		}

		for (unsigned int j = 0; j < numSubkey; j++) {
			DWORD dwNameLen = subKeyBufferLen;
			if (RegEnumKeyEx(hKey, j, subKeyBuffer, &dwNameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
				continue;
			}
			for (unsigned int k = 0; k < dwChecksLength; k++) {
				if (StrStrI(subKeyBuffer, szChecks[k]) != NULL) {
					TCHAR msg[256] = _T("");
					_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key %s get key name %s"), szEntries[i], subKeyBuffer);
					PrintResult(TRUE, msg);
				}
			}
		}

		free(subKeyBuffer);
		RegCloseKey(hKey);
	}
}

void CheckRdtscDiffVmexit()
{
	ULONGLONG tsc1 = 0;
	ULONGLONG tsc2 = 0;
	ULONGLONG avg = 0;
	INT cpuInfo[4] = {};

	// Try this 10 times in case of small fluctuations
	for (INT i = 0; i < 10; i++)
	{
		tsc1 = __rdtsc();
		__cpuid(cpuInfo, 0);
		tsc2 = __rdtsc();

		// Get the delta of the two RDTSC
		avg += (tsc2 - tsc1);
		Sleep(500);
	}

	// We repeated the process 10 times so we make sure our check is as much reliable as we can
	avg = avg / 10;
	PrintResult(!(avg < 1000 && avg > 0), _T("Checking RDTSC which force a VM Exit (cpuid) "));
}
