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
#include <deque>
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

LPVOID Alloc(SIZE_T dwBytes, NTSTATUS *status, HANDLE hEventLog);
NTSTATUS BCryptComputeHash(PUNICODE_STRING Password, string *hash, HANDLE hEventLog);
BOOL Free(PVOID lpMem, HANDLE hEventLog);
LPCWSTR HKEYtoString(HKEY hkey);
LSTATUS RegGetDWORD(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD *dword, HANDLE hEventLog);
LSTATUS RegGetMULTISZ(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, deque<wstring> *multisz, HANDLE hEventLog);
LSTATUS RegGetSZ(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, wstring *sz, HANDLE hEventLog);

BOOLEAN PasswordFilterAccountName(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
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

	HANDLE hEventLog;

	DWORD sAccountName, sCharset, sDictionary, sDiversity, sFullName, sRegex, sRepetition, sSHA1, sStraight;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Armed", &sAccountName, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sAccountName && !PasswordFilterAccountName(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Armed", &sCharset, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sCharset && !PasswordFilterCharset(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, DICTIONARY_REG_FOLDER, L"Armed", &sDictionary, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sDictionary && !PasswordFilterDictionary(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, DIVERSITY_REG_FOLDER, L"Armed", &sDiversity, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sDiversity && !PasswordFilterDiversity(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Armed", &sFullName, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sFullName && !PasswordFilterFullName(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Armed", &sRegex, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sRegex && !PasswordFilterRegex(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, REPETITION_REG_FOLDER, L"Armed", &sRepetition, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sRepetition && !PasswordFilterRepetition(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Armed", &sSHA1, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sSHA1 && !PasswordFilterSHA1(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, STRAIGHT_REG_FOLDER, L"Armed", &sStraight, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;
	if (sSHA1 && !PasswordFilterSHA1(AccountName, FullName, Password, SetOperation))
		goto Cleanup;

	status = TRUE;

Cleanup:
	if (!DeregisterEventSource(hEventLog))
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, EVENT_ERRORS, EVENT_DEREGISTEREVENTSOURCE_ERROR, NULL, 0, 0, NULL, NULL);

	return status;
}

LPVOID Alloc(SIZE_T dwBytes, NTSTATUS *status, HANDLE hEventLog) {
	LPVOID p = NULL;

	__try {
		p = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, dwBytes);
	}
	__except (GetExceptionCode() == STATUS_NO_MEMORY || GetExceptionCode() == STATUS_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_EXECUTION) {
		*status = GetExceptionCode();
		switch (GetExceptionCode()) {
		case STATUS_NO_MEMORY:
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_NO_MEMORY_ERROR, NULL, 0, 0, NULL, NULL);
			break;
		case STATUS_ACCESS_VIOLATION:
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPALLOC_ACCESS_VIOLATION_ERROR, NULL, 0, 0, NULL, NULL);
			break;
		}
		goto Cleanup;
	}

Cleanup:
	return p;
}

NTSTATUS BCryptComputeHash(PUNICODE_STRING Password, string *hash, HANDLE hEventLog) {
	wstring password(Password->Buffer, Password->Length / 2);

	string pBuffer(password.begin(), password.end());

	NTSTATUS status = STATUS_SUCCESS;

	LPCWSTR lpStrings[1];

	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE pbHash = NULL, pbHashObject = NULL;
	stringstream stream;

	switch (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA1_ALGORITHM, NULL, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_NOT_FOUND:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_NOTFOUND_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NO_MEMORY:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_NOMEMORY_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	}

	switch (status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_BUFFER_TOO_SMALL:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_BUFFERTOOSMALL_PROPERTY_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDHANDLE_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NOT_SUPPORTED:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_NOTSUPPORTED_PROPERTY_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pbHashObject = (PBYTE)Alloc(cbHashObject, &status, hEventLog);
	if (pbHashObject == NULL)
		goto Cleanup;

	switch (status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_BUFFER_TOO_SMALL:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_BUFFERTOOSMALL_PROPERTY_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDHANDLE_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NOT_SUPPORTED:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_NOTSUPPORTED_PROPERTY_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pbHash = (PBYTE)Alloc(cbHash, &status, hEventLog);
	if (pbHash == NULL)
		goto Cleanup;

	switch (status = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_BUFFER_TOO_SMALL:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_BUFFERTOOSMALL_HASH_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDHANDLE_ALGORITHM_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_NOT_SUPPORTED:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_NOTSUPPORTED_ALGORITHM_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	}

	switch (status = BCryptHashData(hHash, (PBYTE)pBuffer.c_str(), (ULONG)pBuffer.length(), 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	case STATUS_INVALID_HANDLE:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDHANDLE_HASH_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	}

	switch (status = BCryptFinishHash(hHash, pbHash, cbHash, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_INVALID_HANDLE:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDHANDLE_HASH_ERROR, NULL, 0, 0, lpStrings, NULL);
		goto Cleanup;
	case STATUS_INVALID_PARAMETER:
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDPARAMETER_ERROR, NULL, 0, 0, NULL, NULL);
		goto Cleanup;
	}

	stream << hex << std::setfill('0');
	for (unsigned int i = 0; i < cbHash; i++)
		stream << setw(2) << static_cast<unsigned>(pbHash[i]);
	*hash = stream.str();

Cleanup:
	if (pbHash) {
		(void)SecureZeroMemory(pbHash, cbHash);
		(void)Free(pbHash, hEventLog);
	}

	if (pbHashObject) {
		(void)SecureZeroMemory(pbHashObject, cbHashObject);
		(void)Free(pbHashObject, hEventLog);
	}

	if (hHash) {
		switch (BCryptDestroyHash(hHash)) {
		case STATUS_SUCCESS:
			break;
		case STATUS_INVALID_HANDLE:
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDHANDLE_ALGORITHM_ERROR, NULL, 0, 0, lpStrings, NULL);
			break;
		}
	}

	if (hAlgorithm) {
		switch (BCryptCloseAlgorithmProvider(hAlgorithm, 0)) {
		case STATUS_SUCCESS:
			break;
		case STATUS_INVALID_HANDLE:
			(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, BCRYPT_ERRORS, BCRYPT_INVALIDHANDLE_ALGORITHM_ERROR, NULL, 0, 0, lpStrings, NULL);
			break;
		}
	}

	(void)SecureZeroMemory(&pBuffer, pBuffer.capacity());

	(void)SecureZeroMemory(&password, password.capacity());

	return status;
}

BOOL Free(PVOID lpMem, HANDLE hEventLog) {
	BOOL status;

	LPCWSTR lpStrings[1];

	if (!(status = HeapFree(GetProcessHeap(), 0, lpMem))) {
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, (LPWSTR)&lpStrings[0], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, MEMORY_ERRORS, MEMORY_HEAPFREE_ERROR, NULL, 1, 0, lpStrings, NULL);
		goto Cleanup;
	}

Cleanup:
	return status;
}

LPCWSTR HKEYtoString(HKEY hkey) {
	if (hkey == HKEY_CLASSES_ROOT)
		return L"HKEY_CLASSES_ROOT";
	else if (hkey == HKEY_CURRENT_CONFIG)
		return L"HKEY_CURRENT_CONFIG";
	else if (hkey == HKEY_CURRENT_USER)
		return L"HKEY_CURRENT_USER";
	else if (hkey == HKEY_LOCAL_MACHINE)
		return L"HKEY_LOCAL_MACHINE";
	else if (hkey == HKEY_PERFORMANCE_DATA)
		return L"HKEY_PERFORMANCE_DATA";
	else if (hkey == HKEY_PERFORMANCE_NLSTEXT)
		return L"HKEY_PERFORMANCE_NLSTEXT";
	else if (hkey == HKEY_PERFORMANCE_TEXT)
		return L"HKEY_PERFORMANCE_TEXT";
	else if (hkey == HKEY_USERS)
		return L"HKEY_USERS";
	else
		return L"";
}

LSTATUS RegGetDWORD(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD *dword, HANDLE hEventLog) {
	LSTATUS sec;

	LPCWSTR lpStrings[4];

	DWORD pcbData;

	lpStrings[0] = HKEYtoString(hkey);
	lpStrings[1] = lpSubKey;
	lpStrings[2] = lpValue;

	pcbData = sizeof(DWORD);
	if ((sec = RegGetValueW(hkey, lpSubKey, lpValue, RRF_RT_REG_DWORD, NULL, dword, &pcbData)) != ERROR_SUCCESS) {
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, sec, 0, (LPWSTR)&lpStrings[3], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 4, 0, lpStrings, NULL);
		goto Cleanup;
	}

Cleanup:
	return sec;
}

LSTATUS RegGetMULTISZ(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, deque<wstring> *multisz, HANDLE hEventLog) {
	LSTATUS sec;

	NTSTATUS status;

	LPCWSTR lpStrings[4];

	DWORD pcbData;
	PWCHAR pwChar;

	lpStrings[0] = HKEYtoString(hkey);
	lpStrings[1] = lpSubKey;
	lpStrings[2] = lpValue;

	if ((sec = RegGetValueW(hkey, lpSubKey, lpValue, RRF_RT_REG_MULTI_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, sec, 0, (LPWSTR)&lpStrings[3], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 4, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pwChar = (PWCHAR)Alloc(pcbData * sizeof(WCHAR), &status, hEventLog);
	if (pwChar == NULL)
		goto Cleanup;

	if ((sec = RegGetValueW(hkey, lpSubKey, lpValue, RRF_RT_REG_MULTI_SZ, NULL, pwChar, &pcbData)) != ERROR_SUCCESS) {
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, sec, 0, (LPWSTR)&lpStrings[3], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 4, 0, lpStrings, NULL);
		goto Cleanup;
	}

	while (*pwChar != L'\0') {
		multisz->push_back(pwChar);
		pwChar += wcslen(pwChar) + 1;
	}

Cleanup:
	return sec;
}

LSTATUS RegGetSZ(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, wstring *sz, HANDLE hEventLog) {
	LSTATUS sec;

	NTSTATUS status;

	LPCWSTR lpStrings[4];

	DWORD pcbData;
	PWCHAR pwChar;

	lpStrings[0] = HKEYtoString(hkey);
	lpStrings[1] = lpSubKey;
	lpStrings[2] = lpValue;

	if ((sec = RegGetValueW(hkey, lpSubKey, lpValue, RRF_RT_REG_SZ, NULL, NULL, &pcbData)) != ERROR_SUCCESS) {
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, sec, 0, (LPWSTR)&lpStrings[3], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_SIZE_ERROR, NULL, 4, 0, lpStrings, NULL);
		goto Cleanup;
	}

	pwChar = (PWCHAR)Alloc(pcbData * sizeof(WCHAR), &status, hEventLog);
	if (pwChar == NULL)
		goto Cleanup;

	if ((sec = RegGetValueW(hkey, lpSubKey, lpValue, RRF_RT_REG_SZ, NULL, pwChar, &pcbData)) != ERROR_SUCCESS) {
		(void)FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, sec, 0, (LPWSTR)&lpStrings[3], 0, NULL);
		(void)ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_ERRORS, REGISTRY_REGGETVALUE_VALUE_ERROR, NULL, 4, 0, lpStrings, NULL);
		goto Cleanup;
	}

	sz->assign(pwChar);

Cleanup:
	return sec;
}

BOOLEAN PasswordFilterAccountName(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {
	wstring accountname(AccountName->Buffer, AccountName->Length / 2);
	wstring fullname(FullName->Buffer, FullName->Length / 2);
	wstring password(Password->Buffer, Password->Length / 2);

	wstring aBuffer(AccountName->Buffer, AccountName->Length / 2);

	BOOLEAN status = FALSE;

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD cSensitivity, minLength;
	wstring component, cSeparators;
	wchar_t *p, *context;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_ACCOUNTNAME);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Case sensitivity", &cSensitivity, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetSZ(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Component separators", &cSeparators, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, ACCOUNTNAME_REG_FOLDER, L"Minimum component length", &minLength, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (!cSensitivity) {
		(void)transform(aBuffer.begin(), aBuffer.end(), aBuffer.begin(), ::tolower);
		(void)transform(password.begin(), password.end(), password.begin(), ::tolower);
	}

	p = wcstok_s((wchar_t *)aBuffer.c_str(), cSeparators.c_str(), &context);
	while (p != NULL) {
		component.assign(p);
		if (component.length() >= minLength && !(status = (password.find(component) == wstring::npos))) {
			lpStrings[0] = accountname.c_str();
			lpStrings[1] = fullname.c_str();
			(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_ACCOUNTNAME_WARNING, NULL, 2, 0, lpStrings, NULL);
			goto Cleanup;
		}
		p = wcstok_s(NULL, cSeparators.c_str(), &context);
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_ACCOUNTNAME_SUCCESS, NULL, 2, 0, lpStrings, NULL);
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

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD minDigits, minLowercase, minNonAlphanumeric, minUppercase;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_CHARSET);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Digits", &minDigits, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Lowercase letters", &minLowercase, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Non-alphanumeric character", &minNonAlphanumeric, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, CHARSET_REG_FOLDER, L"Uppercase letters", &minUppercase, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

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

	HANDLE hEventLog;
	LPCWSTR lpStrings[3];

	DWORD cSensitivity;
	deque<wstring> data;
	wstring filename;
	ifstream ifs;
	string entry;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_DICTIONARY);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, DICTIONARY_REG_FOLDER, L"Case sensitivity", &cSensitivity, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetMULTISZ(HKEY_LOCAL_MACHINE, DICTIONARY_REG_FOLDER, L"Data", &data, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (!cSensitivity)
		(void)transform(pBuffer.begin(), pBuffer.end(), pBuffer.begin(), ::tolower);

	for (wstring e : data) {
		filename.assign(REGEX_DATA_FOLDER L"\\");
		filename.append(e);
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

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD maxIdentical, minDifferent;
	wstring charset = L"";

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_DIVERSITY);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, DIVERSITY_REG_FOLDER, L"Maximum number of identical characters", &maxIdentical, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, DIVERSITY_REG_FOLDER, L"Minimum number of different characters", &minDifferent, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

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

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD cSensitivity, minLength;
	wstring component, cSeparators;
	wchar_t *p, *context;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_FULLNAME);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Case sensitivity", &cSensitivity, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetSZ(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Component separators", &cSeparators, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, FULLNAME_REG_FOLDER, L"Minimum component length", &minLength, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (!cSensitivity) {
		(void)transform(fBuffer.begin(), fBuffer.end(), fBuffer.begin(), ::tolower);
		(void)transform(password.begin(), password.end(), password.begin(), ::tolower);
	}

	p = wcstok_s((wchar_t *)fBuffer.c_str(), cSeparators.c_str(), &context);
	while (p != NULL) {
		component.assign(p);
		if (component.length() >= minLength && !(status = (password.find(component) == wstring::npos))) {
			lpStrings[0] = accountname.c_str();
			lpStrings[1] = fullname.c_str();
			(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_ACCOUNTNAME_WARNING, NULL, 2, 0, lpStrings, NULL);
			goto Cleanup;
		}
		p = wcstok_s(NULL, cSeparators.c_str(), &context);
	}

	lpStrings[0] = accountname.c_str();
	lpStrings[1] = fullname.c_str();
	(void)ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, PASSWORDFILTER_FULLNAME_SUCCESS, NULL, 2, 0, lpStrings, NULL);
	status = TRUE;

Cleanup:
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

	HANDLE hEventLog;
	LPCWSTR lpStrings[3];

	deque<wstring> iData, sData;
	wstring filename;
	ifstream ifs;
	string rgx;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_REGEX);

	if (RegGetMULTISZ(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Insurmountable data", &iData, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetMULTISZ(HKEY_LOCAL_MACHINE, REGEX_REG_FOLDER, L"Surmountable data", &sData, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	for (deque<wstring> data : {iData, sData}) {
		for (wstring e : data) {
			filename.assign(REGEX_DATA_FOLDER L"\\");
			filename.append(e);
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

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD cSensitivity, currentCCC = 1, maxICC, minLength;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_REPETITION);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, REPETITION_REG_FOLDER, L"Character sequence case sensitivity", &cSensitivity, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, REPETITION_REG_FOLDER, L"Maximum identical consecutive characters", &maxICC, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, REPETITION_REG_FOLDER, L"Minimum character sequence length", &minLength, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	for (unsigned int i = 1; i < password.length(); i++) {
		if (password.at(i) == password.at(i - 1)) {
			currentCCC++;
			if (currentCCC > maxICC) {
				lpStrings[0] = accountname.c_str();
				lpStrings[1] = fullname.c_str();
				(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_REPETITION_CHARACTER_WARNING, NULL, 2, 0, lpStrings, NULL);
				goto Cleanup;
			}
		}
		else
			currentCCC = 1;
	}

	if (!cSensitivity)
		(void)transform(password.begin(), password.end(), password.begin(), ::tolower);

	for (unsigned int i = password.length() - 1; i >= minLength; i--) {
		for (unsigned int j = 0; j < password.length() - i + 1; j++) {
			if (password.find(password.substr(j, j + i)) < j || password.rfind(password.substr(j, j + i)) > j) {
				lpStrings[0] = accountname.c_str();
				lpStrings[1] = fullname.c_str();
				(void)ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, PASSWORDFILTER_REPETITION_STRING_WARNING, NULL, 2, 0, lpStrings, NULL);
				goto Cleanup;
			}
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

	BOOLEAN status = FALSE;

	HANDLE hEventLog;
	LPCWSTR lpStrings[3];

	deque<wstring> iData, sData;
	wstring filename;
	ifstream ifs;
	string a, b;
	long long left, right, m;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_SHA1);

	if (RegGetMULTISZ(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Insurmountable data", &iData, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (RegGetMULTISZ(HKEY_LOCAL_MACHINE, SHA1_REG_FOLDER, L"Surmountable data", &sData, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

	if (BCryptComputeHash(Password, &b, hEventLog) != STATUS_SUCCESS)
		goto Cleanup;

	for (deque<wstring> data : {iData, sData}) {
		for (wstring e : data) {
			filename.assign(SHA1_DATA_FOLDER L"\\");
			filename.append(e);
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
				if (a.compare(b) < 0)
					left = m + 1;
				else if (a.compare(b) > 0)
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

	HANDLE hEventLog;
	LPCWSTR lpStrings[2];

	DWORD minLength, currentLength = 1;

	hEventLog = RegisterEventSourceW(NULL, EVENTLOG_SOURCE_PASSWORDFILTER_STRAIGHT);

	if (RegGetDWORD(HKEY_LOCAL_MACHINE, STRAIGHT_REG_FOLDER, L"Minimum sequence length", &minLength, hEventLog) != ERROR_SUCCESS)
		goto Cleanup;

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
