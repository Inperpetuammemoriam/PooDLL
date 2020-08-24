/*
 * PooDLL.exe: Command-line tool for testing Password Filter DLLs
 * Copyright (C) 2018-2020  Inperpetuammemoriam
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "pch.h"

#include <iostream>

#include <Windows.h>
#include <SubAuth.h>

#define LIBRARY_NAME L"PooDLL.dll"
#define SET_OPERATION FALSE

using namespace std;

typedef BOOLEAN(*InitializeChangeNotify_t)(void);
typedef NTSTATUS(*PasswordChangeNotify_t)(PUNICODE_STRING, ULONG, PUNICODE_STRING);
typedef BOOLEAN(*PasswordFilter_t)(PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, BOOLEAN);

int wmain(int argc, wchar_t *argv[], wchar_t *envp[]) {
	UNICODE_STRING Password;
	UNICODE_STRING AccountName;
	UNICODE_STRING FullName;
	BOOLEAN SetOperation = SET_OPERATION;

	InitializeChangeNotify_t InitializeChangeNotify;
	PasswordFilter_t PasswordFilter;
	PasswordChangeNotify_t PasswordChangeNotify;

	wcerr << L"PooDLL.exe  Copyright (C) 2018-2020  Inperpetuammemoriam" << endl;
	wcerr << L"This program comes with ABSOLUTELY NO WARRANTY." << endl;
	wcerr << L"This is free software, and you are welcome to redistribute it" << endl;
	wcerr << L"under certain conditions." << endl;
	wcerr << endl;

	if (argc == 1) {
		wcerr << L"Usage: PooDLL.exe password [password [...]]" << endl;
		return 0;
	}

	HMODULE hModule = LoadLibraryW(LIBRARY_NAME);
	if (hModule != NULL) {
		AccountName.MaximumLength = 0;
		AccountName.Length = 0;
		AccountName.Buffer = (PWSTR)L"";
		FullName.MaximumLength = 0;
		FullName.Length = 0;
		FullName.Buffer = (PWSTR)L"";
		InitializeChangeNotify = (InitializeChangeNotify_t)GetProcAddress(hModule, "InitializeChangeNotify");
		if (InitializeChangeNotify == NULL) {
			wcerr << L"Error: GetProcAddress failed with error code " << GetLastError() << L"." << endl;
			goto Cleanup;
		}
		(void)InitializeChangeNotify();
		for (int i = 1; i < argc; i++) {
			Password.MaximumLength = (USHORT)(wcslen(argv[i]) * sizeof(wchar_t) + 1);
			Password.Length = (USHORT)(wcslen(argv[i]) * sizeof(wchar_t));
			Password.Buffer = argv[i];
			PasswordFilter = (PasswordFilter_t)GetProcAddress(hModule, "PasswordFilter");
			if (PasswordFilter == NULL) {
				wcerr << L"Error: GetProcAddress failed with error code " << GetLastError() << L"." << endl;
				goto Cleanup;
			}
			if (PasswordFilter(&AccountName, &FullName, &Password, SetOperation)) {
				wcout << L"PasswordFilter returned TRUE for \"" << Password.Buffer << L"\"." << endl;
				PasswordChangeNotify = (PasswordChangeNotify_t)GetProcAddress(hModule, "PasswordChangeNotify");
				if (PasswordChangeNotify == NULL) {
					wcerr << L"Error: GetProcAddress failed with error code " << GetLastError() << L"." << endl;
					goto Cleanup;
				}
				(void)PasswordChangeNotify(&AccountName, 0, &Password);
			}
			else
				wcout << L"PasswordFilter returned FALSE for \"" << Password.Buffer << L"\"." << endl;
		}
	}
	else
		wcerr << L"Error: LoadLibrary failed with error code " << GetLastError() << L"." << endl;

Cleanup:
	(void)FreeLibrary(hModule);

	return 0;
}
