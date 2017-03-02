/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

   etwlongfuncs.c

Abstract:

    This module contains the routines which implement the
    Event log for files and registry.

--*/

#include "etw.h"

int globalEvent = 4294967295;

//unimplemented
ULONG 
EtwUnregister(
  IN  REGHANDLE RegHandle
)
{
	return ERROR_SUCCESS;
}

//unimplemented
ULONG
EtwRegister(
  IN LPCGUID ProviderId,
  IN PENABLECALLBACK EnableCallback OPTIONAL,
  IN PVOID CallbackContext OPTIONAL,
  OUT PREGHANDLE RegHandle)
{
	return ERROR_SUCCESS;
}

//unimplemented
BOOLEAN
NTAPI
EtwEventEnabled(
  IN  REGHANDLE RegHandle,
  IN  PCEVENT_DESCRIPTOR EventDescriptor
)
{
	return FALSE;
}

//unimplemented
ULONG
NTAPI
EtwWrite(
  IN REGHANDLE RegHandle,
  IN PCEVENT_DESCRIPTOR EventDescriptor,
  IN ULONG UserDataCount,
  IN PEVENT_DATA_DESCRIPTOR UserData)
{
	return ERROR_SUCCESS;
}

//unimplemented
NTSTATUS
NTAPI
EtwReplyNotification(ULONG parameter)
{
	return STATUS_SUCCESS;
}

ULONG
NTAPI
EtwWriteEndScenario(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData)
{
	return ERROR_SUCCESS;
}

ULONG
EtwWriteStartScenario(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData)
{
	return ERROR_SUCCESS;
}

NTSTATUS
NTAPI
EtwWriteString(
   IN REGHANDLE RegHandle,
   IN UCHAR Level,
   IN ULONGLONG Keyword,
   IN OPTIONAL LPCGUID ActivityId,
   IN PCWSTR String)
{
	return STATUS_SUCCESS;
}

ULONG 
NTAPI 
EtwEnableTrace( 
	ULONG enable, 
	ULONG flag, 
	ULONG level, 
	LPCGUID guid, 
	TRACEHANDLE hSession)
{
	return ERROR_SUCCESS;	
}

NTSTATUS 
NTAPI 
EtwWriteTransfer(
  IN           REGHANDLE RegHandle,
  IN           PCEVENT_DESCRIPTOR EventDescriptor,
  IN OPTIONAL  LPCGUID ActivityId,
  IN OPTIONAL  LPCGUID RelatedActivityId,
  IN      	   ULONG UserDataCount,
  IN OPTIONAL  PEVENT_DATA_DESCRIPTOR UserData
)
{
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
EtwEventWriteFull(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    USHORT EventProperty,
    LPCGUID ActivityId,
    LPCGUID RelatedActivityId,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData)
{
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
EtwWriteUMSecurityEvent (
    PCEVENT_DESCRIPTOR EventDescriptor,
    USHORT EventProperty,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData)
{
	return STATUS_SUCCESS;
}

NTSTATUS 
NTAPI 
EmClientQueryRuleState(LPCGUID a1, PEM_RULE_STATE a2)
{
  int compose; // eax@3
  int other; // esi@3
  LONG exchange; // edx@8
  BOOLEAN verification; // al@8
  NTSTATUS status; // [sp+Ch] [bp-4h]@1
  LONG *pointer = NULL; // [sp+18h] [bp+8h]@5

  status = STATUS_SUCCESS;
  if ( a1 && a2 )
  {
    *a2 = 1;
    compose = 1;
    other = compose;
    if ( (compose && pointer)!= 0 )
    {
      if ( _interlockedbittestandset(pointer, 0 ))
        ExfAcquirePushLockExclusive((PEX_PUSH_LOCK)pointer);
      _InterlockedExchangeAdd(pointer, 1u);
      exchange = _InterlockedExchangeAdd(pointer, 0xFFFFFFFFu);
      verification = (BOOLEAN)_InterlockedExchangeAdd(pointer, 0xFFFFFFFFu);
      if ( verification & 2 && !(verification & 4) )
        ExfTryToWakePushLock((PEX_PUSH_LOCK)pointer);
    }
    else
    {
      status = STATUS_NOT_FOUND;
    }
  }
  else
  {
    status = STATUS_INVALID_PARAMETER;
  }
  return status;
}

NTSTATUS EtwKernelTraceDiagnosticEvent(BOOLEAN a1, int a2, BOOLEAN var, int a4, int a5)
{
  NTSTATUS result; // eax@3
  PVOID WnodeEventItem; // [sp+8h] [bp-40h]@1
  BOOLEAN verification; // [sp+Ch] [bp-3Ch]@1
  int v8; // [sp+10h] [bp-38h]@2
  int v9; // [sp+14h] [bp-34h]@2
  int v10; // [sp+20h] [bp-28h]@1
  int v11; // [sp+24h] [bp-24h]@1
  int v12; // [sp+28h] [bp-20h]@1
  int v13; // [sp+2Ch] [bp-1Ch]@1
  int v14; // [sp+34h] [bp-14h]@1
  __int64 v15; // [sp+38h] [bp-10h]@1
  int v16; // [sp+40h] [bp-8h]@1

  memset(&WnodeEventItem, 0, 0x40u);
  v10 = *(DWORD *)(ULONGLONG)a2;
  v11 = *(DWORD *)(ULONGLONG)(a2 + 4);
  v12 = *(DWORD *)(ULONGLONG)(a2 + 8);
  v13 = *(DWORD *)(ULONGLONG)(a2 + 12);
  verification = var;
  v15 = a4;
  v16 = a5;
  v14 = 1179648;
  WnodeEventItem = (PVOID)64;
  if ( globalEvent != -1 )
  {
    v9 = 0;
    v8 = globalEvent;
    IoWMIWriteEvent(&WnodeEventItem);
  }
  result = 1;
  if ( a1 & 1 )
  {
    v9 = 0;
    v8 = 1;
    result = IoWMIWriteEvent(&WnodeEventItem);
  }
  return result;
}