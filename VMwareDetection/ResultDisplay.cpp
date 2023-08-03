#include "pch.h"

#include "ResultDisplay.h"


void PrintResult(BOOL result, const TCHAR* szMsg)
{
	PrintCheckText(szMsg);
	PrintCheckResult(result);
}

void PrintCheckText(const TCHAR* szMsg)
{
	int alignment = 95;

	if (_tcslen(szMsg) > alignment)
		_tprintf(TEXT("[*] %-*.*s...  "), alignment, alignment, szMsg);
	else
		_tprintf(TEXT("[*] %-*.*s     "), alignment, alignment, szMsg);
}

void PrintSubCheckText(const TCHAR* szMsg)
{
	int alignment = 95;

	if (_tcslen(szMsg) > alignment)
		_tprintf(TEXT("[-] %-*.*s...  \n"), alignment, alignment, szMsg);
	else
		_tprintf(TEXT("[-] %-*.*s     \n"), alignment, alignment, szMsg);
}

void PrintCheckResult(BOOL result)
{
	if (result == TRUE)
		PrintDetected();
	else
		PrintNotDetected();
}

void PrintDetected()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	WORD savedAttributes = consoleInfo.wAttributes;

	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED);
	_tprintf(TEXT("[ BAD  ]\n"));
	SetConsoleTextAttribute(hConsole, savedAttributes);
}

void PrintNotDetected() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	WORD savedAttributes = consoleInfo.wAttributes;

	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
	_tprintf(TEXT("[ GOOD ]\n"));
	SetConsoleTextAttribute(hConsole, savedAttributes);
}

void PrintLastError(LPCTSTR szFunction) {
	DWORD errorCode = GetLastError();
	LPTSTR errorMessage = NULL;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errorMessage, 0, NULL);

	if (errorMessage != NULL) {
		std::TOUT << szFunction << " failed with error: " << errorCode << std::endl;
		std::TOUT << "Error Message: " << errorMessage << std::endl;
	}

	LocalFree(errorMessage);
}

