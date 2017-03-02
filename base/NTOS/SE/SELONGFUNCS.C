/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    selongfuncs.c

Abstract:

    Executive security components Initialization.

--*/

#include "pch.h"

#pragma hdrstop

#include "adt.h"
#include <string.h>

#define SID_HASH_SIZE 32 

typedef ULONG_PTR SID_HASH_ENTRY;

BOOLEAN NTAPI SeAccessCheckFromState 	(PSECURITY_DESCRIPTOR  	SecurityDescriptor,
		PTOKEN_ACCESS_INFORMATION  	PrimaryTokenInformation,
		PTOKEN_ACCESS_INFORMATION  	ClientTokenInformation,
		ACCESS_MASK  	DesiredAccess,
		ACCESS_MASK  	PreviouslyGrantedAccess,
		PPRIVILEGE_SET *  	Privileges,
		PGENERIC_MAPPING  	GenericMapping,
		KPROCESSOR_MODE  	AccessMode,
		PACCESS_MASK  	GrantedAccess,
		PNTSTATUS  	AccessStatus 
	) 	
{
	PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext = NULL;
	PACCESS_MASK LocalGrantedAccess; 
	PGENERIC_MAPPING LocalGenericMapping;
	PNTSTATUS LocalAccessStatus;
	PPRIVILEGE_SET *LocalPrivileges = NULL;
	
	SubjectSecurityContext->ClientToken = 0;
	SubjectSecurityContext->ImpersonationLevel = 0;
	SubjectSecurityContext->ProcessAuditId = 0;
	SubjectSecurityContext->PrimaryToken = 0;
	
	LocalGrantedAccess = GrantedAccess;
	LocalGenericMapping = GenericMapping;
	LocalAccessStatus = AccessStatus;
	LocalPrivileges = LocalPrivileges;
	
	if(ClientTokenInformation)
	{
		SubjectSecurityContext->ClientToken = 0;
		SubjectSecurityContext->ImpersonationLevel = ClientTokenInformation->ImpersonationLevel;
	}else{
		SubjectSecurityContext->ClientToken = 0;
	}
	return SeAccessCheck(
						SecurityDescriptor, 
						SubjectSecurityContext,
						1,
						DesiredAccess,
						PreviouslyGrantedAccess,
						LocalPrivileges,
						LocalGenericMapping,
						AccessMode,
						LocalGrantedAccess,
						LocalAccessStatus);
}

BOOLEAN NTAPI SeTokenIsWriteRestricted ( 	IN PACCESS_TOKEN  	Token	) 	
{
    PAGED_CODE();
    return (((PTOKEN)Token)->TokenFlags & TOKEN_HAS_RESTORE_PRIVILEGE) != 0;
}

