/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    ktm.h

Abstract:

    This module contains platform independent interlocked functions.

--*/

NTSTATUS ZwOpenResourceManager(
  OUT     PHANDLE ResourceManagerHandle,
  IN      ACCESS_MASK DesiredAccess,
  IN      HANDLE TmHandle,
  IN      LPGUID ResourceManagerGuid,
  IN 	  POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS ZwOpenEnlistment(
  OUT     PHANDLE EnlistmentHandle,
  IN      ACCESS_MASK DesiredAccess,
  IN      HANDLE RmHandle,
  IN      LPGUID EnlistmentGuid,
  IN 	  POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS NTAPI TmCreateEnlistment(
	PHANDLE EnlistmentHandle, 
	KPROCESSOR_MODE PreviousMode, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	PKRESOURCEMANAGER ResourceManager, 
	PKTRANSACTION Transaction, 
	ULONG CreateOptions, 
	NOTIFICATION_MASK NotificationMask, 
	PVOID EnlistmentKey
);