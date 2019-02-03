/*
 * PasswordFilter.dll: DLL implementing the Password Filter functions
 * Copyright (C) 2018-2019  Inperpetuammemoriam
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
#include "stdafx.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>

#include <bcrypt.h>
#include <ntstatus.h>
#include <SubAuth.h>

#include "..\MSG\MSG.h"

#define EVENTLOG_SOURCE_PASSWORDFILTER L"PasswordFilter"
#define EVENTLOG_SOURCE_PASSWORDFILTER_ACCOUNTNAME L"PasswordFilterAccountName"
#define EVENTLOG_SOURCE_PASSWORDFILTER_BINGO L"PasswordFilterBingo"
#define EVENTLOG_SOURCE_PASSWORDFILTER_CHARSET L"PasswordFilterCharset"
#define EVENTLOG_SOURCE_PASSWORDFILTER_DICTIONARY L"PasswordFilterDictionary"
#define EVENTLOG_SOURCE_PASSWORDFILTER_DIVERSITY L"PasswordFilterDiversity"
#define EVENTLOG_SOURCE_PASSWORDFILTER_FULLNAME L"PasswordFilterFullName"
#define EVENTLOG_SOURCE_PASSWORDFILTER_REGEX L"PasswordFilterRegex"
#define EVENTLOG_SOURCE_PASSWORDFILTER_REPETITION L"PasswordFilterRepetition"
#define EVENTLOG_SOURCE_PASSWORDFILTER_SHA1 L"PasswordFilterSHA1"
#define EVENTLOG_SOURCE_PASSWORDFILTER_STRAIGHT L"PasswordFilterStraight"
#define MANUFACTURER L"PS0"
#define SOLUTION L"PasswordFilter"

#define DATA_FOLDER L"C:\\ProgramData\\" MANUFACTURER L"\\" SOLUTION
#define REG_FOLDER L"SOFTWARE\\" MANUFACTURER L"\\" SOLUTION
#define ACCOUNTNAME_REG_FOLDER REG_FOLDER L"\\AccountName"
#define BINGO_REG_FOLDER REG_FOLDER L"\\Bingo"
#define CHARSET_REG_FOLDER REG_FOLDER L"\\Charset"
#define DICTIONARY_REG_FOLDER REG_FOLDER L"\\Dictionary"
#define DIVERSITY_REG_FOLDER REG_FOLDER L"\\Diversity"
#define FULLNAME_REG_FOLDER REG_FOLDER L"\\FullName"
#define REGEX_DATA_FOLDER DATA_FOLDER L"\\Regex"
#define REGEX_REG_FOLDER REG_FOLDER L"\\Regex"
#define REPETITION_REG_FOLDER REG_FOLDER L"\\Repetition"
#define SHA1_DATA_FOLDER DATA_FOLDER L"\\SHA1"
#define SHA1_REG_FOLDER REG_FOLDER L"\\SHA1"
#define STRAIGHT_REG_FOLDER REG_FOLDER L"\\Straight"

using namespace std;

BOOLEAN PasswordFilterAccountName(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterBingo(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterCharset(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterDictionary(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterFullName(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterDiversity(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterRegex(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterRepetition(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterSHA1(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
BOOLEAN PasswordFilterStraight(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);

extern "C" __declspec(dllexport) BOOLEAN InitializeChangeNotify(void) {
	HANDLE hEventLog;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER);

	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, INITIALIZECHANGENOTIFY, NULL, 0, 0, NULL, NULL);

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return TRUE;
}

extern "C" __declspec(dllexport) NTSTATUS PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword) {
	wstring username(UserName->Buffer, UserName->Length / 2);

	HANDLE hEventLog;
	LPCWSTR lpStrings[1];

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER);

	lpStrings[0] = username.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDCHANGENOTIFY, NULL, 1, 0, lpStrings, NULL);

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return STATUS_SUCCESS;
}

extern "C" __declspec(dllexport) BOOLEAN PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[3];

	DWORD pcbData, sAccountName, sBingo, sCharset, sDictionary, sDiversity, sFullName, sRegex, sRepetition, sSHA1;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sAccountName, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" ACCOUNTNAME_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sAccountName && !PasswordFilterAccountName(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, BINGO_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sBingo, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" BINGO_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sBingo && !PasswordFilterBingo(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sCharset, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" CHARSET_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sCharset && !PasswordFilterCharset(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, DICTIONARY_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sDictionary, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" DICTIONARY_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sDictionary && !PasswordFilterDictionary(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, DIVERSITY_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sDiversity, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" DIVERSITY_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sDiversity && !PasswordFilterDiversity(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sFullName, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" FULLNAME_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sFullName && !PasswordFilterFullName(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sRegex, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REGEX_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sRegex && !PasswordFilterRegex(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REPETITION_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sRepetition, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REPETITION_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sRepetition && !PasswordFilterRepetition(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Armed", RRF_RT_DWORD, NULL, &sSHA1, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" SHA1_REG_FOLDER L"\\Armed";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (sSHA1 && !PasswordFilterSHA1(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	status = TRUE;

Cleanup:
	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterAccountName(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	wstring aBuffer(AccountName->Buffer, AccountName->Length / 2);

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	PWCHAR cSeparators = NULL;
	DWORD pcbData, cSensitivity, minLength;
	wstring component;
	wchar_t *p, *context;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_ACCOUNTNAME);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Case sensitivity", RRF_RT_DWORD, NULL, &cSensitivity, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" ACCOUNTNAME_REG_FOLDER L"\\Case sensitivity";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Component separators", RRF_RT_REG_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" ACCOUNTNAME_REG_FOLDER L"\\Component separators";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	cSeparators = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, pcbData * sizeof(WCHAR));
	if (cSeparators == NULL) {
		lpStrings[0] = L"cSeparators";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Component separators", RRF_RT_REG_SZ, NULL, cSeparators, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" ACCOUNTNAME_REG_FOLDER L"\\Component separators";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Minimum component length", RRF_RT_DWORD, NULL, &minLength, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" ACCOUNTNAME_REG_FOLDER L"\\Minimum component length";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (!cSensitivity) {
		(void)transform(aBuffer.begin(), aBuffer.end(), aBuffer.begin(), ::tolower);
		(void)transform(password.begin(), password.end(), password.begin(), ::tolower);
	}

	p = wcstok_s((wchar_t *)aBuffer.c_str(), cSeparators, &context);
	while (p != NULL) {
		component.assign(p);
		if (component.length() >= minLength && !(status = (password.find(component) == wstring::npos))) {
			lpStrings[0] = accountname.c_str();
			lpStrings[1] = fullname.c_str();
			(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_ACCOUNTNAME_WARNING, NULL, 2, 0, lpStrings, NULL);
			goto Cleanup;
		}
		p = wcstok_s(NULL, cSeparators, &context);
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_ACCOUNTNAME_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	if (cSeparators) {
		if (!HeapFree(GetProcessHeap(), 0, cSeparators)) {
			lpStrings[0] = L"cSeparators";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}

	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterBingo(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD pcbData, maxCCC, currentCCC = 1;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_BINGO);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, BINGO_REG_FOLDER, L"Maximum consecutive character count", RRF_RT_DWORD, NULL, &maxCCC, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" BINGO_REG_FOLDER L"\\Maximum consecutive character count";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	for (unsigned int i = 1; i < password.length(); i++) {
		if (password.at(i) == password.at(i - 1)) {
			currentCCC++;
			if (currentCCC > maxCCC) {
				lpStrings[0] = accountname.c_str();
				lpStrings[1] = fullname.c_str();
				(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_BINGO_WARNING, NULL, 2, 0, lpStrings, NULL);
				goto Cleanup;
			}
		}
		else
			currentCCC = 1;
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_BINGO_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterCharset(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD pcbData, minDigits, minLowercase, minNonAlphanumeric, minUppercase;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_CHARSET);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Digits", RRF_RT_DWORD, NULL, &minDigits, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" CHARSET_REG_FOLDER L"\\Digits";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Lowercase letters", RRF_RT_DWORD, NULL, &minLowercase, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" CHARSET_REG_FOLDER L"\\Lowercase letters";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Non-alphanumeric character", RRF_RT_DWORD, NULL, &minNonAlphanumeric, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" CHARSET_REG_FOLDER L"\\Non-alphanumeric character";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Uppercase letters", RRF_RT_DWORD, NULL, &minUppercase, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" CHARSET_REG_FOLDER L"\\Uppercase letters";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	for (unsigned int i = 0; i < password.length(); i++) {
		if (isdigit(password.at(i))) {
			if (minDigits > 0)
				minDigits--;
		}
		else if (islower(password.at(i))) {
			if (minLowercase > 0)
				minLowercase--;
		}
		else if (isupper(password.at(i))) {
			if (minUppercase > 0)
				minUppercase--;
		}
		else {
			if (minNonAlphanumeric > 0)
				minNonAlphanumeric--;
		}
	}

	if (minDigits > 0) {
		lpStrings[0] = accountname.c_str();
		lpStrings[1] = fullname.c_str();
		(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_CHARSET_DIGITS_WARNING, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (minLowercase > 0) {
		lpStrings[0] = accountname.c_str();
		lpStrings[1] = fullname.c_str();
		(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_CHARSET_LOWERCASE_WARNING, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (minNonAlphanumeric > 0) {
		lpStrings[0] = accountname.c_str();
		lpStrings[1] = fullname.c_str();
		(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_CHARSET_NONALPHANUMERIC_WARNING, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (minUppercase > 0) {
		lpStrings[0] = accountname.c_str();
		lpStrings[1] = fullname.c_str();
		(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_CHARSET_UPPERCASE_WARNING, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_CHARSET_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterDictionary(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	string pBuffer(password.begin(), password.end());

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[3];

	PWCHAR data = NULL, p;
	DWORD pcbData, cSensitivity;
	wstring filename;
	ifstream ifs;
	string entry;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_DICTIONARY);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, DICTIONARY_REG_FOLDER, L"Case sensitivity", RRF_RT_DWORD, NULL, &cSensitivity, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" DICTIONARY_REG_FOLDER L"\\Case sensitivity";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, DICTIONARY_REG_FOLDER, L"Data", RRF_RT_REG_MULTI_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" DICTIONARY_REG_FOLDER L"\\Data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	data = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, pcbData * sizeof(WCHAR));
	if (data == NULL) {
		lpStrings[0] = L"data";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, DICTIONARY_REG_FOLDER, L"Data", RRF_RT_REG_MULTI_SZ, NULL, data, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" DICTIONARY_REG_FOLDER L"\\Data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (!cSensitivity)
		(void)transform(pBuffer.begin(), pBuffer.end(), pBuffer.begin(), ::tolower);

	p = data;
	while (*p != L'\0') {
		filename.assign(REGEX_DATA_FOLDER L"\\");
		filename.append(p);
		p += wcslen(p) + 1;
		ifs.open(filename);
		if (!ifs.is_open()) {
			lpStrings[0] = filename.c_str();
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, FILESTREAM_ERRORS, FILESTREAM_OPEN_ERROR, NULL, 1, 0, lpStrings, NULL);
			goto Cleanup;
		}
		(void)getline(ifs, entry);
		if (pBuffer.find(entry)) {
			lpStrings[0] = accountname.c_str();
			lpStrings[1] = fullname.c_str();
			lpStrings[1] = filename.c_str();
			(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_DICTIONARY_WARNING, NULL, 3, 0, lpStrings, NULL);
			goto Cleanup;
		}
		ifs.close();
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_DICTIONARY_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	if (data) {
		if (!HeapFree(GetProcessHeap(), 0, data)) {
			lpStrings[0] = L"data";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}

	(void)SecureZeroMemory(&pBuffer, pBuffer.capacity());

	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterDiversity(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD pcbData, maxIdentical, minDifferent;
	wstring charset = L"";

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_DIVERSITY);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, DIVERSITY_REG_FOLDER, L"Maximum number of identical characters", RRF_RT_DWORD, NULL, &maxIdentical, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" DIVERSITY_REG_FOLDER L"\\Maximum number of identical characters";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, DIVERSITY_REG_FOLDER, L"Minimum number of different characters", RRF_RT_DWORD, NULL, &minDifferent, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" DIVERSITY_REG_FOLDER L"\\Minimum number of different characters";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	for (unsigned int i = 0; i < password.length(); i++) {
		if (count(password.begin(), password.end(), password.at(i)) > maxIdentical) {
			lpStrings[0] = accountname.c_str();
			lpStrings[1] = fullname.c_str();
			(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_DIVERSITY_MAXIDENTICAL_WARNING, NULL, 2, 0, lpStrings, NULL);
			goto Cleanup;
		}
	}

	for (unsigned int i = 0; i < password.length(); i++) {
		if (charset.find(password.at(i)))
			charset.append(1, password.at(i));
	}

	if (charset.length() < minDifferent) {
		lpStrings[0] = accountname.c_str();
		lpStrings[1] = fullname.c_str();
		(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_DIVERSITY_MINDIFFERENT_WARNING, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_DIVERSITY_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	(void)SecureZeroMemory(&charset, charset.capacity());

	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterFullName(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	wstring fBuffer(FullName->Buffer, FullName->Length / 2);

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	PWCHAR cSeparators = NULL;
	DWORD pcbData, cSensitivity, minLength;
	wstring component;
	wchar_t *p, *context;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_FULLNAME);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Case sensitivity", RRF_RT_DWORD, NULL, &cSensitivity, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" FULLNAME_REG_FOLDER L"\\Case sensitivity";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Component separators", RRF_RT_REG_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" FULLNAME_REG_FOLDER L"\\Component separators";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	cSeparators = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, pcbData * sizeof(WCHAR));
	if (cSeparators == NULL) {
		lpStrings[0] = L"cSeparators";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Component separators", RRF_RT_REG_SZ, NULL, cSeparators, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" FULLNAME_REG_FOLDER L"\\Component separators";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Minimum component length", RRF_RT_DWORD, NULL, &minLength, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" FULLNAME_REG_FOLDER L"\\Minimum component length";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (!cSensitivity) {
		(void)transform(fBuffer.begin(), fBuffer.end(), fBuffer.begin(), ::tolower);
		(void)transform(password.begin(), password.end(), password.begin(), ::tolower);
	}

	p = wcstok_s((wchar_t *)fBuffer.c_str(), cSeparators, &context);
	while (p != NULL) {
		component.assign(p);
		if (component.length() >= minLength && !(status = (password.find(component) == wstring::npos))) {
			lpStrings[0] = accountname.c_str();
			lpStrings[1] = fullname.c_str();
			(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_ACCOUNTNAME_WARNING, NULL, 2, 0, lpStrings, NULL);
			goto Cleanup;
		}
		p = wcstok_s(NULL, cSeparators, &context);
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_FULLNAME_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	if (cSeparators) {
		if (!HeapFree(GetProcessHeap(), 0, cSeparators)) {
			lpStrings[0] = L"cSeparators";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}

	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterRegex(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	string pBuffer(password.begin(), password.end());

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[3];

	PWCHAR iData = NULL, sData = NULL, p;
	DWORD pcbData;
	wstring filename;
	ifstream ifs;
	string rgx;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_REGEX);

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Insurmountable data", RRF_RT_REG_MULTI_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REGEX_REG_FOLDER L"\\Insurmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	iData = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, pcbData * sizeof(WCHAR));
	if (iData == NULL) {
		lpStrings[0] = L"iData";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Insurmountable data", RRF_RT_REG_MULTI_SZ, NULL, iData, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REGEX_REG_FOLDER L"\\Insurmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Surmountable data", RRF_RT_REG_MULTI_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REGEX_REG_FOLDER L"\\Surmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	sData = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, pcbData * sizeof(WCHAR));
	if (sData == NULL) {
		lpStrings[0] = L"sData";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Surmountable data", RRF_RT_REG_MULTI_SZ, NULL, sData, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REGEX_REG_FOLDER L"\\Surmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	for (PWCHAR data : {iData, sData}) {
		p = data;
		while (*p != L'\0') {
			filename.assign(REGEX_DATA_FOLDER L"\\");
			filename.append(p);
			p += wcslen(p) + 1;
			ifs.open(filename);
			if (!ifs.is_open()) {
				lpStrings[0] = filename.c_str();
				(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, FILESTREAM_ERRORS, FILESTREAM_OPEN_ERROR, NULL, 1, 0, lpStrings, NULL);
				goto Cleanup;
			}
			(void)getline(ifs, rgx);
			if (regex_search(pBuffer, regex(rgx))) {
				if (data == sData && SetOperation) {
					lpStrings[0] = accountname.c_str();
					lpStrings[1] = fullname.c_str();
					lpStrings[2] = filename.c_str();
					(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_REGEX_SETOPERATION_WARNING, NULL, 3, 0, lpStrings, NULL);
					status = TRUE;
					goto Cleanup;
				}
				else {
					lpStrings[0] = accountname.c_str();
					lpStrings[1] = fullname.c_str();
					lpStrings[2] = filename.c_str();
					(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_REGEX_WARNING, NULL, 3, 0, lpStrings, NULL);
					goto Cleanup;
				}
			}
			ifs.close();
		}
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_REGEX_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	if (ifs.is_open())
		ifs.close();

	if (sData) {
		if (!HeapFree(GetProcessHeap(), 0, sData)) {
			lpStrings[0] = L"sData";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}

	if (iData) {
		if (!HeapFree(GetProcessHeap(), 0, iData)) {
			lpStrings[0] = L"iData";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}

	(void)SecureZeroMemory(&pBuffer, pBuffer.capacity());

	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterRepetition(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD pcbData, cSensitivity, minLength;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_REPETITION);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REPETITION_REG_FOLDER, L"Case sensitivity", RRF_RT_DWORD, NULL, &cSensitivity, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REPETITION_REG_FOLDER L"\\Case sensitivity";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, REPETITION_REG_FOLDER, L"Minimum sequence length", RRF_RT_DWORD, NULL, &minLength, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" REPETITION_REG_FOLDER L"\\Minimum sequence length";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if (!cSensitivity)
		(void)transform(password.begin(), password.end(), password.begin(), ::tolower);

	for (unsigned int i = password.length() - 1; i >= minLength; i--) {
		for (unsigned int j = 0; j < password.length() - i + 1; j++)
			if (password.find(password.substr(j, j + i)) < j || password.rfind(password.substr(j, j + i)) > j) {
				lpStrings[0] = accountname.c_str();
				lpStrings[1] = fullname.c_str();
				(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_REPETITION_WARNING, NULL, 2, 0, lpStrings, NULL);
				goto Cleanup;
			}
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_REPETITION_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterSHA1(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	string pBuffer(password.begin(), password.end());

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[3];

	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	PBYTE pbHashObject = NULL, pbHash = NULL;
	DWORD cbData = 0, cbHashObject = 0, cbHash = 0;

	stringstream b;

	PWCHAR iData = NULL, sData = NULL, p;
	DWORD pcbData;
	wstring filename;
	ifstream ifs;
	string a;
	long long left, right, m;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_SHA1);

	switch (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA1_ALGORITHM, NULL, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_NOT_FOUND:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_NOTFOUND_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NO_MEMORY:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_NOMEMORY_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	}

	switch (BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_BUFFER_TOO_SMALL:
		lpStrings[0] = L"cbOutput";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_BUFFERTOOSMALL_PROPERTY_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		lpStrings[0] = L"hObject";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDHANDLE_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NOT_SUPPORTED:
		lpStrings[0] = L"pszProperty";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_NOTSUPPORTED_PROPERTY_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (pbHashObject == NULL) {
		lpStrings[0] = L"pbHashObject";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	switch (BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_BUFFER_TOO_SMALL:
		lpStrings[0] = L"cbOutput";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_BUFFERTOOSMALL_PROPERTY_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		lpStrings[0] = L"hObject";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDHANDLE_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NOT_SUPPORTED:
		lpStrings[0] = L"pszProperty";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_NOTSUPPORTED_PROPERTY_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (pbHash == NULL) {
		lpStrings[0] = L"pbHash";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	switch (BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_BUFFER_TOO_SMALL:
		lpStrings[0] = L"cbHashObject";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_BUFFERTOOSMALL_HASH_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		lpStrings[0] = L"hAlgorithm";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDHANDLE_ALGORITHM_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NOT_SUPPORTED:
		lpStrings[0] = L"hAlgorithm";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_NOTSUPPORTED_ALGORITHM_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	switch (BCryptHashData(hHash, (PBYTE)pBuffer.c_str(), (ULONG)pBuffer.length(), 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		lpStrings[0] = L"hHash";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDHANDLE_HASH_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	switch (BCryptFinishHash(hHash, pbHash, cbHash, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_INVALID_HANDLE:
		lpStrings[0] = L"";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDHANDLE_HASH_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	}

	b << hex << std::setfill('0');
	for (unsigned int i = 0; i < cbHash; i++)
		b << setw(2) << static_cast<unsigned>(pbHash[i]);

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Insurmountable data", RRF_RT_REG_MULTI_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" SHA1_REG_FOLDER L"\\Insurmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	iData = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, pcbData * sizeof(WCHAR));
	if (iData == NULL) {
		lpStrings[0] = L"iData";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Insurmountable data", RRF_RT_REG_MULTI_SZ, NULL, iData, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" SHA1_REG_FOLDER L"\\Insurmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Surmountable data", RRF_RT_REG_MULTI_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" SHA1_REG_FOLDER L"\\Surmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	sData = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, pcbData * sizeof(WCHAR));
	if (sData == NULL) {
		lpStrings[0] = L"sData";
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Surmountable data", RRF_RT_REG_MULTI_SZ, NULL, sData, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" SHA1_REG_FOLDER L"\\Surmountable data";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	for (PWCHAR data : {iData, sData}) {
		p = data;
		while (*p != L'\0') {
			filename.assign(SHA1_DATA_FOLDER L"\\");
			filename.append(p);
			p += wcslen(p) + 1;
			ifs.open(filename, fstream::ate);
			if (!ifs.is_open()) {
				lpStrings[0] = filename.c_str();
				(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, FILESTREAM_ERRORS, FILESTREAM_OPEN_ERROR, NULL, 1, 0, lpStrings, NULL);
				goto Cleanup;
			}
			left = 0;
			right = ifs.tellg() / 42;
			(void)ifs.seekg(fstream::beg);
			while (left <= right) {
				m = (left + right) / 2;
				(void)ifs.seekg(m * 42, ifs.beg);
				(void)getline(ifs, a);
				(void)transform(a.begin(), a.end(), a.begin(), ::tolower);
				if (a.compare(b.str()) < 0)
					left = m + 1;
				else if (a.compare(b.str()) > 0)
					right = m - 1;
				else {
					if (data == sData && SetOperation) {
						lpStrings[0] = accountname.c_str();
						lpStrings[1] = fullname.c_str();
						lpStrings[2] = filename.c_str();
						(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_SHA1_SETOPERATION_WARNING, NULL, 3, 0, lpStrings, NULL);
						status = TRUE;
						goto Cleanup;
					}
					else {
						lpStrings[0] = accountname.c_str();
						lpStrings[1] = fullname.c_str();
						lpStrings[2] = filename.c_str();
						(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_SHA1_WARNING, NULL, 3, 0, lpStrings, NULL);
						goto Cleanup;
					}
				}
			}
			ifs.close();
		}
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_SHA1_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	if (ifs.is_open())
		ifs.close();

	if (sData) {
		if (!HeapFree(GetProcessHeap(), 0, sData)) {
			lpStrings[0] = L"sData";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}

	if (iData) {
		if (!HeapFree(GetProcessHeap(), 0, iData)) {
			lpStrings[0] = L"iData";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}

	if (pbHash) {
		(void)SecureZeroMemory(pbHash, cbHash);
		if (!HeapFree(GetProcessHeap(), 0, pbHash)) {
			lpStrings[0] = L"pbHash";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}
	if (pbHashObject) {
		(void)SecureZeroMemory(pbHashObject, cbHashObject);
		if (!HeapFree(GetProcessHeap(), 0, pbHashObject)) {
			lpStrings[0] = L"pbHashObject";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		}
	}
	if (hHash) {
		switch (BCryptDestroyHash(hHash)) {
		case STATUS_SUCCESS:
			break;
		case STATUS_INVALID_HANDLE:
			lpStrings[0] = L"hHash";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDHANDLE_ALGORITHM_ERROR, NULL, 1, 0, lpStrings, NULL);
			break;
		}
	}
	if (hAlgorithm) {
		switch (BCryptCloseAlgorithmProvider(hAlgorithm, 0)) {
		case STATUS_SUCCESS:
			break;
		case STATUS_INVALID_HANDLE:
			lpStrings[0] = L"hAlgorithm";
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, CRYPTO_ERRORS, CRYPTO_INVALIDHANDLE_ALGORITHM_ERROR, NULL, 1, 0, lpStrings, NULL);
			break;
		}
	}

	(void)SecureZeroMemory(&pBuffer, pBuffer.capacity());

	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

BOOLEAN PasswordFilterStraight(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	BOOLEAN status = FALSE;

	LSTATUS sec;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD pcbData, minLength, currentLength = 1;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_STRAIGHT);

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(HKEY_LOCAL_MACHINE, STRAIGHT_REG_FOLDER, L"Minimum sequence length", RRF_RT_DWORD, NULL, &minLength, &pcbData)) != ERROR_SUCCESS) {
		lpStrings[0] = L"HKEY_LOCAL_MACHINE\\" STRAIGHT_REG_FOLDER L"\\Minimum sequence length";
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, sec, 0, (LPWSTR)&lpStrings[1], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 2, 0, lpStrings, NULL);
		goto Cleanup;
	}

	for (unsigned int i = 1; i < password.length(); i++) {
		if (password.at(i) == password.at(i - 1) - 1 || password.at(i) == password.at(i - 1) + 1) {
			currentLength++;
			if (currentLength > minLength) {
				lpStrings[0] = accountname.c_str();
				lpStrings[1] = fullname.c_str();
				(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_STRAIGHT_WARNING, NULL, 2, 0, lpStrings, NULL);
				goto Cleanup;
			}
		}
		else
			currentLength = 1;
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_STRAIGHT_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
	(void)SecureZeroMemory(&password, password.capacity());

	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}
