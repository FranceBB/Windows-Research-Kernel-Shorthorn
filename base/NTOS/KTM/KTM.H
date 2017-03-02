/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    ktm.h

Abstract:

    This module contains the private data structures and procedure
    prototypes for the transactions management system.

--*/

#include "ntos.h"
#include "ntimage.h"
#include "fsrtl.h"
#include "zwapi.h"
#include "pool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "safeboot.h"
#include "triage.h"

POBJECT_TYPE TmTransactionObjectType;
POBJECT_TYPE resource;
ULONG_PTR __security_cookie;
POBJECT_TYPE TmEnlistmentObjectType;
typedef unsigned __int64 QWORD;

PKMUTANT globalMutex;
int compare =1;
PWSTR local;
POBJECT_TYPE globalObject;
PCUNICODE_STRING unknown;
PSECURITY_DESCRIPTOR globalSecurity;
PCWSTR manager = NULL;
HANDLE handle = NULL;
PFAST_MUTEX mutant;
QWORD helper = 0;
PVOID globalHum =0 ;
PVOID globalSecond = 0;