#include "pch.h"

int main()
{
	_tprintf(TEXT("VMWare Detection\n"));
	CheckVmwareFiles();
	CheckVmwareDevices();
	CheckVmwareMac();
	CheckVmwareReg();
	CheckVmwareSMBIOS();
	CheckVmwareACPI();
	CheckVmwareProcesses();
	CheckDiskdrive();
	CheckCPUID();
	CheckBIOSSerialNumberWMI();
	CheckModelComputerSystemWMI();
	CheckManufacturerComputerSystemWMI();
	CheckCPUFanWMI();
	CheckChacheMemoryWMI();
	CheckVoltageProbeWMI();
	CheckThermalZoneInfoWMI();
	CheckCIMMemoryWMI();
	CheckCIMSensorWMI();
	CheckCIMNumericSensorWMI();
	CheckCIMTemperatureSensorWMI();
	CheckCIMVoltageSensorWMI();
	CheckRegServicesDiskEnum();
	CheckRegDiskEnum();
	CheckRdtscDiffVmexit();

	_tprintf(_T("\n\nAnalysis done."));
	getchar();
	return 0;
}