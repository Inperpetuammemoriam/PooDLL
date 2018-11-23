;/*
; * PasswordFilter.dll: DLL implementing the Password Filter functions
; * Copyright (C) 2018  Inperpetuammemoriam
; *
; * This program is free software: you can redistribute it and/or modify
; * it under the terms of the GNU General Public License as published by
; * the Free Software Foundation, either version 3 of the License, or
; * (at your option) any later version.
; *
; * This program is distributed in the hope that it will be useful,
; * but WITHOUT ANY WARRANTY; without even the implied warranty of
; * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; * GNU General Public License for more details.
; *
; * You should have received a copy of the GNU General Public License
; * along with this program.  If not, see <https://www.gnu.org/licenses/>.
; */

LanguageNames=(English=0x409:MSG00409)

MessageIdTypedef=DWORD

;// Categories

MessageId=
SymbolicName=CRYPTO_ERRORS
Language=English
Crypto Errors
.

MessageId=
SymbolicName=EVENT_ERRORS
Language=English
Eventlog Errors
.

MessageId=
SymbolicName=FILESTREAM_ERRORS
Language=English
Filestream Errors
.

MessageId=
SymbolicName=MEMORY_ERRORS
Language=English
Memory Errors
.

MessageId=
SymbolicName=REGISTRY_ERRORS
Language=English
Registry Errors
.

;// Messages

MessageId=
SymbolicName=CRYPTO_BUFFERTOOSMALL_HASH_ERROR
Language=English
The size of the hash object specified by the %1 parameter is not large enough to hold the hash object.
.

MessageId=
SymbolicName=CRYPTO_BUFFERTOOSMALL_PROPERTY_ERROR
Language=English
The buffer size specified by the %1 parameter is not large enough to hold the property value.
.

MessageId=
SymbolicName=CRYPTO_INVALIDHANDLE_ERROR
Language=English
The handle in the %1 parameter is not valid.
.

MessageId=
SymbolicName=CRYPTO_INVALIDHANDLE_ALGORITHM_ERROR
Language=English
The algorithm handle in the %1 parameter is not valid.
.

MessageId=
SymbolicName=CRYPTO_INVALIDHANDLE_HASH_ERROR
Language=English
The hash handle in the %1 parameter is not valid.
.

MessageId=
SymbolicName=CRYPTO_INVALIDPARAMETER_ERROR
Language=English
One or more parameters are not valid.
.

MessageId=
SymbolicName=CRYPTO_NOMEMORY_ERROR
Language=English
A memory allocation failure occurred.
.

MessageId=
SymbolicName=CRYPTO_NOTFOUND_ERROR
Language=English
No provider was found for the specified algorithm ID.
.

MessageId=
SymbolicName=CRYPTO_NOTSUPPORTED_ALGORITHM_ERROR
Language=English
The algorithm provider specified by the %1 parameter does not support the hash interface.
.

MessageId=
SymbolicName=CRYPTO_NOTSUPPORTED_PROPERTY_ERROR
Language=English
The named property specified by the %1 parameter is not supported.
.

MessageId=
SymbolicName=EVENT_DEREGISTEREVENTSOURCE_ERROR
Language=English
Could not deregister event source.
.

MessageId=
SymbolicName=FILESTREAM_OPEN_ERROR
Language=English
Could not open file "%1".
.

MessageId=
SymbolicName=INITIALIZECHANGENOTIFY
Language=English
PasswordFilter.dll  Copyright (C) 2018  Inperpetuammemoriam\r\n
This program comes with ABSOLUTELY NO WARRANTY.\r\n
This is free software, and you are welcome to redistribute it\r\n
under certain conditions.
.

MessageId=
SymbolicName=MEMORY_HEAPALLOC_ERROR
Language=English
Memory allocation for %1 failed.
.

MessageId=
SymbolicName=MEMORY_HEAPFREE_ERROR
Language=English
Could not free %1.
.

MessageId=
SymbolicName=PASSWORDCHANGENOTIFY
Language=English
Password for %1 has been changed.
.

MessageId=
SymbolicName=PASSWORDFILTER_ACCOUNTNAME_SUCCESS
Language=English
No component of AccountName was found in the new password for %1 (%2). The new password was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_ACCOUNTNAME_WARNING
Language=English
A component of AccountName was found in the new password of %1 (%2). The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_BINGO_SUCCESS
Language=English
The new password for %1 (%2) contains no sequences of consecutive characters longer than the specified threshold. The new password was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_BINGO_WARNING
Language=English
The new password for %1 (%2) contains sequences of consecutive characters longer than the specified threshold. The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_CHARSET_SUCCESS
Language=English
The new password for %1 (%2) contains the configured number of elements from the given sets. The new password was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_CHARSET_DIGITS_WARNING
Language=English
The new password for %1 (%2) does not contain enough digits. The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_CHARSET_LOWERCASE_WARNING
Language=English
The new password for %1 (%2) does not contain enough lowercase characters. The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_CHARSET_NONALPHANUMERIC_WARNING
Language=English
The new password for %1 (%2) does not contain enough non-alphanumeric characters. The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_CHARSET_UPPERCASE_WARNING
Language=English
The new password for %1 (%2) does not contain enough uppercase characters. The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_DICTIONARY_SUCCESS
Language=English
The new password for %1 (%2) contains no entries of the specified dictionaries. The new password was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_DICTIONARY_WARNING
Language=English
The new password for %1 (%2) contains an entry of the dictionary in "%3". The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_DIVERSITY_SUCCESS
Language=English
The new password for %1 (%2) meets the diversity criteria. The new password was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_DIVERSITY_MAXIDENTICAL_WARNING
Language=English
The new password for %1 (%2) contains too many identical characters. The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_DIVERSITY_MINDIFFERENT_WARNING
Language=English
The new password for %1 (%2) does not contain enough differenct characters. The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_FULLNAME_SUCCESS
Language=English
No component of FullName was found in the new password for %1 (%2). The new password was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_FULLNAME_WARNING
Language=English
A component of FullName was found in the new password of %1 (%2). The new password was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_REGEX_SETOPERATION_WARNING
Language=English
New password for %1 (%2) matched a regular expression in file "%3" but was accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_REGEX_SUCCESS
Language=English
New password for %1 (%2) matched no regular expression and was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_REGEX_WARNING
Language=English
New password for %1 (%2) matched a regular expression in file "%3" and was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_REPETITION_SUCCESS
Language=English
New password for %1 (%2) contains no repeating character sequences and was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_REPETITION_WARNING
Language=English
New password for %1 (%2) contains repeating character sequences and was therefore rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_SHA1_SETOPERATION_WARNING
Language=English
New password for %1 (%2) was found in file "%3" but accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_SHA1_SUCCESS
Language=English
New password for %1 (%2) was not found in SHA1 data and therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_SHA1_WARNING
Language=English
New password for %1 (%2) was found in file "%3" and rejected.
.

MessageId=
SymbolicName=PASSWORDFILTER_STRAIGHT_SUCCESS
Language=English
The new password for %1 (%2) contains no invalid character sequences. The new password was therefore accepted.
.

MessageId=
SymbolicName=PASSWORDFILTER_STRAIGHT_WARNING
Language=English
The new password for %1 (%2) contains an invalid character sequence. The new password was therefore rejected.
.

MessageId=
SymbolicName=REGISTRY_REGGETVALUE_SIZE_ERROR
Language=English
Could not get the registry key "%1" value's size. (%2)
.

MessageId=
SymbolicName=REGISTRY_REGGETVALUE_VALUE_ERROR
Language=English
Could not get the registry value for "%1". (%2)
.
