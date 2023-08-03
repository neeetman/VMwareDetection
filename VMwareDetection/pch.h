#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include <winsock2.h>
#include <tchar.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <shlwapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <intrin.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <TlHelp32.h>
#include <Windows.h>

#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

#include "Utils.h"
#include "ResultDisplay.h"
#include "VMwareDetection.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wbemuuid.lib")

#ifdef _UNICODE
#define TOUT wcout
#else
#define TOUT cout
#endif

typedef std::basic_string<TCHAR> _tstring;
#endif //PCH_H