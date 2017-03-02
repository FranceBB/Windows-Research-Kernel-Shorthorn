/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

   ktmlongfuncs.c

Abstract:

    This module contains the routines which implement the
    transactions for files and registry.

--*/

#include <ktm.h>

//new status codes
#define STATUS_TRANSACTIONMANAGER_NOT_ONLINE 0xC0190052

POBJECT_TYPE TmEnlistmentObjectType;

POBJECT_TYPE TmTransactionManagerObjectType;

POBJECT_TYPE TmResourceManagerObjectType;

KENLISTMENT_STATE TmpDefaultTmObject;

KMUTANT TmpInitializationMutex;

HANDLE TmpDefaultTmHandle = NULL;

POBJECT_TYPE TmTransactionManagerObjectType;

const UNICODE_STRING TmpLogName = RTL_CONSTANT_STRING(L"\\KTMLOG");

NTSTATUS NTAPI NtQueryInformationTransaction(
	HANDLE Handle, 
	TRANSACTION_INFORMATION_CLASS TransactionInformationClass, 
	PVOID *Address, 
	SIZE_T Length, 
	PULONG ReturnLength
)
{
   return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtQueryInformationTransactionManager(
	HANDLE Handle, 
	TRANSACTIONMANAGER_INFORMATION_CLASS InformationClass, 
	PVOID Address, 
	ULONG Length, 
	ULONG ReturnLength
)
{
	return 0x00000000;
}

//unimplemented
NTSTATUS NTAPI NtOpenTransactionManager(
  OUT     PHANDLE TmHandle,
  IN      ACCESS_MASK DesiredAccess,
  IN  	  POBJECT_ATTRIBUTES ObjectAttributes,
  IN  	  PUNICODE_STRING LogFileName,
  IN  	  LPGUID TmIdentity,
  IN  	  ULONG OpenOptions
)
{
	return 0x00000000;
}
//unimplemented
NTSTATUS NTAPI NtOpenResourceManager(
	PHANDLE EnlistmentHandle, 
	ACCESS_MASK DesiredAccess, 
	HANDLE TmHandle, 
	LPGUID ResourceManagerGuid, 
	POBJECT_ATTRIBUTES ObjectAttributes
)
{
  POBJECT_HANDLE_INFORMATION information; // edx@1
  NTSTATUS result; // eax@2
  ULONG *address; // eax@5
  HANDLE pointer; // [sp+14h] [bp-50h]@16
  PVOID Object; // [sp+1Ch] [bp-48h]@12
  int attributes; // [sp+24h] [bp-40h]@1
  KPROCESSOR_MODE AccessMode; // [sp+28h] [bp-3Ch]@4
  PVOID otherObject; // [sp+2Ch] [bp-38h]@1
  PVOID object; // [sp+30h] [bp-34h]@1
  NTSTATUS status; // [sp+34h] [bp-30h]@12
  ULONG resource; // [sp+38h] [bp-2Ch]@9
  CPPEH_RECORD ms_exc; // [sp+4Ch] [bp-18h]@5

  information = 0;
  otherObject = 0;
  object = 0;
  attributes = 0;
  if ( DesiredAccess && ResourceManagerGuid )
  {
    AccessMode = KeGetPreviousMode();
    if ( AccessMode )
    {
      ms_exc.registration.TryLevel = 0;
      address = (ULONG *)EnlistmentHandle;
      if ( EnlistmentHandle >= (PHANDLE)MmUserProbeAddress )
        address = (ULONG *)MmUserProbeAddress;
      if ( ResourceManagerGuid && 3 )
        ExRaiseDatatypeMisalignment();
      resource = ResourceManagerGuid->Data1;
      ms_exc.registration.TryLevel = -2;
      information = 0;
    }
    else
    {
      resource = ResourceManagerGuid->Data1;
      if ( ObjectAttributes )
        attributes = ObjectAttributes->Attributes;
    }
    ms_exc.registration.TryLevel = 1;
    result = ObReferenceObjectByHandle(
               TmHandle,
               1,
               TmTransactionManagerObjectType,
               AccessMode,
               &Object,
               information);
    otherObject = Object;
    status = result;
    if ( result >= 0 )
    {
      result = STATUS_SUCCESS;
      if ( result )
      {
        result = STATUS_SUCCESS;//TmpFindResourceManagerTm(&resource);
        status = result;
        if ( result >= 0 )
        {
          result = ObOpenObjectByPointer(
                     object,
                     attributes,
                     0,
                     DesiredAccess,
                     TmResourceManagerObjectType,
                     AccessMode,
                     &pointer);
          status = result;
          if ( result >= 0 )
          {
            result = STATUS_SUCCESS;
            ms_exc.registration.TryLevel = 1;
          }
        }
      }
      else
      {
        status = STATUS_TRANSACTIONMANAGER_NOT_ONLINE;
      }
    }
    ms_exc.registration.TryLevel = -2;
    if ( otherObject )
      result = (NTSTATUS)ObfDereferenceObject(otherObject);
    if ( object )
      result = (NTSTATUS)ObfDereferenceObject(object);
  }
  else
  {
    result = STATUS_INVALID_PARAMETER;
  }
  return result;
}

//unimplemented
NTSTATUS NTAPI NtOpenEnlistment(
  OUT     PHANDLE EnlistmentHandle,
  IN      ACCESS_MASK DesiredAccess,
  IN      HANDLE RmHandle,
  IN      LPGUID EnlistmentGuid,
  IN 	  POBJECT_ATTRIBUTES ObjectAttributes
)
{
	if(!EnlistmentGuid || !DesiredAccess)
	{
		return 0xC000000Du;
	}else{
		return NtOpenResourceManager(EnlistmentHandle, DesiredAccess, RmHandle, EnlistmentGuid, ObjectAttributes);
	}
}

//unimplemented
NTSTATUS NTAPI NtCreateResourceManager(
  OUT     PHANDLE ResourceManagerHandle,
  IN      ACCESS_MASK DesiredAccess,
  IN      HANDLE TmHandle,
  IN  	  LPGUID ResourceManagerGuid,
  IN 	  POBJECT_ATTRIBUTES ObjectAttributes,
  IN 	  ULONG CreateOptions,
  IN 	  PUNICODE_STRING Description
)
{
    return STATUS_SUCCESS;
}

//unimplemented
NTSTATUS NTAPI NtCreateTransactionManager(
  OUT     PHANDLE TmHandle,
  IN      ACCESS_MASK DesiredAccess,
  IN      POBJECT_ATTRIBUTES ObjectAttributes,
  IN 	  PUNICODE_STRING LogFileName,
  IN 	  ULONG CreateOptions,
  IN 	  ULONG CommitStrength
)
{
	return STATUS_SUCCESS;
}

LONG NTAPI TmpReleaseTransactionMutex(PKTRANSACTION transaction)
{
  return KeReleaseMutex(&transaction->TreeTx->Mutex, 0);
}

NTSTATUS NTAPI TmpTxActionDoRollback(PKTRANSACTION Object, int Unused)
{
  ULONG Count; 
  PVOID Propagation; 
  BOOLEAN verification; 
  ULONG comparation; 
  PKTRANSACTION localTransaction; 
  NTSTATUS recursive; 
  NTSTATUS resp; 

  Count = Object->PrePrepareRequiredEnlistmentCount;
  resp = 0;
  if ( (Count == 3 || Count == 4) && Object->PrepareRequiredEnlistmentCount & 0x800000 )
    resp = STATUS_SUCCESS;
#if defined(_i386_)
  Object->RollbackDpc.DpcListEntry.Blink = (struct _LIST_ENTRY *)__readfsdword(292);
#else
  Object->RollbackDpc.DpcListEntry.Blink = (struct _LIST_ENTRY *)__readgsqword(292);
#endif
  Object->PrePrepareRequiredEnlistmentCount = 6;
  Object->TransactionHistory[1].Payload = 3;
  KeSetEvent(&Object->OutcomeEvent, 0, 0);
  Propagation = Object->PromotePropagation;
  if ( Propagation )
    resp = STATUS_SUCCESS;//TmpNotifyEnlistment(Propagation, ~(unsigned __int8)(Object->PrepareRequiredEnlistmentCount >> 6) & 1, 8, 1);
  verification = (BOOLEAN)&Object->OutcomeRequiredEnlistmentCount;
  if ( (!Object->PromotePropagation || verification != Object->PendingResponses) )
    resp = STATUS_SUCCESS;//TmpNotifyAllEnlistmentsTransaction(8, 269);
  comparation = Object->PrepareRequiredEnlistmentCount;
  if ( comparation & 0x100 && comparation & 0x400 )
  {
#if defined(_i386_)
    localTransaction = (PKTRANSACTION)Object->Timeout.HighPart;
#else
    localTransaction = (PKTRANSACTION)(ULONGLONG)Object->Timeout.HighPart;
#endif
    while ( (LONG *)localTransaction != &Object->Timeout.HighPart )
    {
      recursive = TmpTxActionDoRollback((PKTRANSACTION)((char *)localTransaction - 168), 0);
      localTransaction = *(PKTRANSACTION *)&localTransaction->OutcomeEvent.Header.Type;
      resp = recursive;
    }
  }
  Object->PrePrepareRequiredEnlistmentCount = 9;
  //TmpFinalizeTransaction(Object);
  return resp;
}

NTSTATUS NTAPI TmRollbackTransaction(PKTRANSACTION Transaction, BOOLEAN Wait)
{
  ULONG count; // ecx@1
  PKTRANSACTION localTransaction; // edi@3
  NTSTATUS result; // eax@3
  BOOLEAN verification; // [sp+17h] [bp-19h]@1

  DbgPrintEx(0x6Cu, 0x80000020u, "KTM:  TmRollbackTransaction for tx %lx\n", Transaction);
  verification = TRUE;
  count = Transaction->PrepareRequiredEnlistmentCount;
  if ( !(count & 0x400) || count & 0x100 )
  {
    result = Transaction->PrePrepareRequiredEnlistmentCount;
    if ( result == 1 || result == 8 || result == 2 || result == 11 || result == 3 && count & 2 )
    {
      if ( Transaction->TransactionHistory[2].RecordType )
      {
        result = TmpTxActionDoRollback(Transaction, 0);
      }
      else
      {
        Transaction->PrePrepareRequiredEnlistmentCount = 9;
        Transaction->TransactionHistory[1].Payload = 3;
        KeSetEvent(&Transaction->OutcomeEvent, 0, 0);
        result = STATUS_SUCCESS;//TmpFinalizeTransaction(Transaction);
      }
    }
    else
    {
      if ( result != 6 )
        Transaction->TransactionHistory[1].Payload = 3;
    }
  }
  else
  {
    localTransaction = (PKTRANSACTION)Transaction->Description.Buffer;
    TmpReleaseTransactionMutex(Transaction);	
    result = TmRollbackTransaction(localTransaction, FALSE);
  }
  if ( verification )
    result = TmpReleaseTransactionMutex(Transaction);
  return result;
}

NTSTATUS NTAPI TmSetCurrentTransaction(HANDLE Transaction)
{
  NTSTATUS result; // eax@1
  PKTRANSACTION currentTransaction; // ecx@1
  PKTRANSACTION setTransaction; // edx@1

  result = 0;
#if defined(_i386_)
  currentTransaction = (PKTRANSACTION)__readfsdword(292);
  setTransaction = (PKTRANSACTION)currentTransaction->LastLsn.ullOffset;
  if ( !((ULONG)currentTransaction[1].RollbackDpc.SystemArgument2 & 0x10) && setTransaction )
#else
  currentTransaction = (PKTRANSACTION)__readgsqword(292);
  setTransaction = (PKTRANSACTION)currentTransaction->LastLsn.ullOffset;
  if ( !((ULONGLONG)currentTransaction[1].RollbackDpc.SystemArgument2 & 0x10) && setTransaction )
#endif
    setTransaction = Transaction;
  else
    result = STATUS_UNSUCCESSFUL;
  return result;
}

/* unimplemented*/
void TmInitDefaultTemporaryTm(PKTRANSACTION  a1, PKTRANSACTION  a2)
{
	;
}

/* unimplemented*/
BOOLEAN TmRmIsNotificationQueueEmpty_Temporary(IN  PKTRANSACTION Transaction)
{
  return TRUE;
}

int TmReferenceTransactionByPointer(PVOID pointer)
{
  ObfReferenceObject(pointer);
  return 0;
}

int TmDereferenceTransaction(PVOID object)
{
  ObfDereferenceObject(object);
  return 0;
}

NTSTATUS TmReferenceTransactionByHandle(HANDLE Object, HANDLE other)
{
  NTSTATUS result; // eax@1

  result = ObReferenceObjectByHandle(Object, 0, TmTransactionObjectType, 0, &Object, 0);
  if ( result >= 0 )
	 other = Object;
  return result;
}

NTSTATUS TmReferenceResourceManagerByHandle(HANDLE Object, HANDLE other)
{
  NTSTATUS result; // eax@1

  result = ObReferenceObjectByHandle(Object, 0, resource, 0, &Object, 0);
  if ( result >= 0 )
    other = Object;
  return result;
}

NTSTATUS TmReferenceEnlistmentKey(PKENLISTMENT Enlistment, PRKMUTEX Mutex)
{
  PVOID receive; // eax@7
  NTSTATUS status; // [sp+8h] [bp-4h]@1

  status = 0;
  if ( Mutex )
  {
    KeWaitForSingleObject(&Enlistment->EnlistmentId.Data4[4], 0, 0, 0, 0);
#if defined(_i386_)
  	if ( (ULONG)Enlistment->NextSameRm.Blink[3].Flink & 2 )
#else
  	if ( (ULONGLONG)Enlistment->NextSameRm.Blink[3].Flink & 2 )
#endif
    {
      receive = Enlistment->Key;
      if ( !receive )
      {
        status = 0xC0000001u;
        goto LABEL_4;
      }
      if ( receive == (PVOID)-1 )
      {
        status = 0xC000009Au;
        goto LABEL_4;
      }
      Enlistment->Key = (char *)receive + 1;
    }	
    *(DWORD *)&Mutex->Header.Type = Enlistment->NotificationMask;
LABEL_4:
    KeReleaseMutex((PRKMUTEX)&Enlistment->EnlistmentId.Data4[4], 0);
    return status;
  }
  return STATUS_SUCCESS;
}

LONG TmpStartDefaultTm()
{
  NTSTATUS receiveStatus; // eax@5
  NTSTATUS status; // eax@6
  CHAR *string; // [sp-8h] [bp-5Ch]@7
  NTSTATUS setStatus; // [sp-4h] [bp-58h]@7
  int size; // [sp+Ch] [bp-48h]@5
  LSA_UNICODE_STRING DestinationString; // [sp+2Ch] [bp-28h]@4
  PVOID Object; // [sp+34h] [bp-20h]@6
  NTSTATUS otherStatus; // [sp+38h] [bp-1Ch]@1
  CPPEH_RECORD ms_exc[2]; // [sp+3Ch] [bp-18h]@1

  otherStatus = 0;
  KeWaitForSingleObject(&TmpInitializationMutex, 0, 0, 0, 0);
  ms_exc[1].registration.TryLevel = 0;
  if ( !TmpDefaultTmObject )
  {
    DestinationString.Buffer = (PWSTR)ExAllocatePoolWithQuotaTag((POOL_TYPE)9, 0x200u, 0x6E4C6D54u);
    if ( !DestinationString.Buffer )
    {
      otherStatus = 0xC000009Au;
      goto Finalization;
    }
    DestinationString.Length = 0;
    DestinationString.MaximumLength = 512;
    RtlCopyUnicodeString(&DestinationString, 0);
    RtlAppendUnicodeToString(&DestinationString, L"\\SystemRoot\\System32\\Config");
    RtlAppendUnicodeStringToString(&DestinationString, &TmpLogName);
    size = 24;
    receiveStatus = STATUS_SUCCESS;//ZwCreateTransactionManager(&TmpDefaultTmHandle, 0, &size, &DestinationString, 0, 0);
    otherStatus = receiveStatus;
    if ( receiveStatus < 0 )
    {
      setStatus = receiveStatus;
      string = "KTM: Creating default TM instance returned %d\n";
    }
    else
    {
      status = ObReferenceObjectByHandle(TmpDefaultTmHandle, 0, TmTransactionManagerObjectType, 0, &Object, 0);
      TmpDefaultTmObject = (KENLISTMENT_STATE)Object;
      otherStatus = status;
      if ( status >= 0 )
        goto Finalization;
      setStatus = status;
      string = "KTM: Referencing default TM instance returned %d\n";
    }
    DbgPrintEx(0x6Cu, 0, string, setStatus);
    goto Finalization;
  }
  otherStatus = 0;
Finalization:
  ms_exc[1].registration.TryLevel = -1;
  return KeReleaseMutex(&TmpInitializationMutex, 0);
}

LONG NtStartTm()
{
  return TmpStartDefaultTm();
}

BOOLEAN TmInitSystemPhase2()
{
  return TmpStartDefaultTm() >= 0;
}

int TmDereferenceResourceManager(PVOID object)
{
  ObfDereferenceObject(object);
  return 0;
}

NTSTATUS TmDereferenceEnlistmentKey(PKENLISTMENT Enlistment, PBOOLEAN verification)
{
  PVOID other; // eax@2
  PVOID localkey; // eax@4
  NTSTATUS status; // [sp+Ch] [bp-4h]@1

  status = 0;
  KeWaitForSingleObject(&Enlistment->EnlistmentId.Data4[4], 0, 0, 0, 0);
#if defined(_i386_)
  if ( (unsigned int)Enlistment->NextSameRm.Blink[3].Flink & 2 )
#else
  if ( (ULONGLONG)Enlistment->NextSameRm.Blink[3].Flink & 2 )
#endif
  {
    other = Enlistment->Key;
    if ( other )
    {
      localkey = (char *)other - 1;
      Enlistment->Key = localkey;
      if ( verification )
        *verification = localkey == 0;
    }
    else
    {
      status = 0xC0000001u;
    }
  }
  else
  {
    status = STATUS_SUCCESS;
  }
  KeReleaseMutex((PRKMUTEX)&Enlistment->EnlistmentId.Data4[4], 0);
  return status;
}

//reimplement
NTSTATUS TmCurrentTransaction()
{
  ULONG transaction; // ecx@1
  NTSTATUS result; // eax@1
#if defined(_i386_)
  transaction = __readfsdword(292);
  result = *(DWORD *)(transaction + 116);
  if ( *(BYTE *)(__readfsdword(292) + 288) != 1 )
  {
      if ( *(BYTE *)(transaction + 592) & 0x10 )
#else
  transaction = (ULONG)(ULONGLONG)__readgsqword(292);  
  result = *(DWORD *)(ULONGLONG)(transaction + 116);
  if ( *(BYTE *)(__readgsqword(292) + 288) != 1 )
  {
      if ( *(BYTE *)(ULONGLONG)(transaction + 592) & 0x10 )
#endif
    {
      if ( result != -1 )
      {
LABEL_5:
        if ( result )
          return result;
        return -1;
      }
    }
    else
    {
      if ( result )
      {
#if defined(_i386_)
        result = *(DWORD *)(result + 4012);
#else
        result = *(DWORD *)(ULONGLONG)(result + 4012);
#endif
        goto LABEL_5;
      }
    }
  }
  return -1;
}

BOOLEAN TmpIsNotificationMaskValid(BYTE byte, BOOLEAN verification)
{
  if ( verification )
  {
    if ( byte & 8 && !(byte & 0x207) )
      return TRUE;
  }
  else
  {
    if ( byte & 8
      && !(byte & 0xF0)
      && (!(byte & 2) || byte & 4)
      && !((byte & 2) == (0 & byte))
      && byte & 5 )
      return TRUE;
  }
  return FALSE;
}

PLIST_ENTRY NTAPI TmpMakeTransactionManagerPermanent(PLIST_ENTRY list)
{
  PLIST_ENTRY result; // eax@1

  result = list;
  *((BYTE *)&result[-1] - 1) |= 0x10u;
  return result;
}

LONG NTAPI TmpMakeResourceManagerPermanent(PKRESOURCEMANAGER manager)
{
  PLIST_ENTRY listaEntry; // esi@1

  listaEntry = manager->PendingPropReqListHead.Flink;
  KeWaitForSingleObject(&listaEntry->Blink, 0, 0, 0, 0);
  ++listaEntry[35].Flink;
  if ( listaEntry[35].Flink == (struct _LIST_ENTRY *)1 )
    TmpMakeTransactionManagerPermanent(listaEntry);
  return KeReleaseMutex((PRKMUTEX)&listaEntry->Blink, 0);
}

NTSTATUS TmInitializeEnlistment(
	PKENLISTMENT Enlistment, 
	PKRESOURCEMANAGER Object, 
	PKTRANSACTION Transaction, 
	UUID Uuid, 
	ULONG CreateOptions, 
	NOTIFICATION_MASK Mutex, 
	PVOID EnlistmentKey)
{
  ULONG receive; // edi@1
  PKENLISTMENT localEnlistment; // esi@3
  PVOID length; // eax@3
  KENLISTMENT_STATE state; // ecx@5
  PKRESOURCEMANAGER localManager; // edi@6
  KENLISTMENT_STATE newState; // edx@6
  ULONG refCount; // eax@8
  PLIST_ENTRY listEntry; // edx@11
  ULONG compare; // eax@16
  PLIST_ENTRY listEntry2; // eax@19
  PLIST_ENTRY listEntry3; // ecx@19
  PLIST_ENTRY listEntry4; // edx@20
  PVOID key; // eax@29
  NTSTATUS resultStatus; // eax@31
  NTSTATUS otherResult; // ebx@32
  PKRESOURCEMANAGER customManager; // eax@34
  PLIST_ENTRY Flink; // edx@41
  PKRESOURCEMANAGER localResourceManager; // [sp+4h] [bp-8h]@1
  PVOID localHandle; // [sp+8h] [bp-4h]@2
  PKENLISTMENT otherEnlistment; // [sp+1Ch] [bp+10h]@34
  PKMUTANT Mutexa; // [sp+28h] [bp+1Ch]@5
  int count;
  
  receive = 0;
  localResourceManager = 0;
  if ( !TmpIsNotificationMaskValid((BYTE)&Uuid.Data4[0],Uuid.Data2 & 1) )
    return 0xC000000Du;
  localHandle = ExAllocatePoolWithTag(0, 0x20u, 0x4E466D54u);
  if ( !localHandle )
    return 0xC000009Au;
  localEnlistment = (PKENLISTMENT)Transaction;
  TmReferenceTransactionByPointer(Transaction);
  ObfReferenceObject(Object);
  Enlistment->NamespaceLink.Links = (PVOID)1;
  Enlistment->Key = (PVOID)1;
  Enlistment->NextSameRm.Blink = (struct _LIST_ENTRY *)Object;
  Enlistment->Flags = (UCHAR)&Uuid.Data4[0];
  length = localHandle;
  Enlistment->cookie = 0xB00B0003u;
  Enlistment->ResourceManager = (PKRESOURCEMANAGER)Transaction;
  Enlistment->NotificationMask = (UCHAR)&Uuid.Data4[4];
  Enlistment->State = 0;
  Enlistment->DynamicNameInformationLength = (ULONG)(ULONGLONG)length;
  if ( Uuid.Data1 )
  {
    Enlistment->NamespaceLink.Expired = (UCHAR)Uuid.Data1;
    localEnlistment = (PKENLISTMENT)Transaction;
    receive = 0;
  }
  else
  {
    ExUuidCreate((UUID *)&Enlistment->NamespaceLink.Expired);
  }
  Enlistment->KeyRefCount = receive;
  Enlistment->RecoveryInformation = (PVOID)(ULONGLONG)receive;
  Enlistment->RecoveryInformationLength = receive;
  Enlistment->DynamicNameInformation = (PVOID)(ULONGLONG)receive;
  KeInitializeMutex((PRKMUTEX)&Enlistment->EnlistmentId.Data4[4], receive);
  Enlistment->CrmEnlistmentTmId.Data2 = (USHORT)receive;
  memset(Enlistment->CrmEnlistmentTmId.Data4, 0, 0xA0u);
  Mutexa = (PKMUTANT)localEnlistment->EnlistmentId.Data4;
  KeWaitForSingleObject(localEnlistment->EnlistmentId.Data4, 0, 0, 0, 0);
  state = localEnlistment->History[14].NewState;
  if ( state == TmpDefaultTmObject )
  {
    localManager = Object;
    newState = (KENLISTMENT_STATE)Object->PendingPropReqListHead.Flink;
    if ( newState )
      localEnlistment->History[14].NewState = newState;
    else
      Object->PendingPropReqListHead.Flink = (struct _LIST_ENTRY *)TmpDefaultTmObject;
  }
  else
  {
    key = Object->PendingPropReqListHead.Flink;
    if ( (PVOID)state != key)
    {
      //resultStatus = TmpEnlistAsSubordinateTm(key, state, localEnlistment, (int)&localResourceManager);
      resultStatus = STATUS_SUCCESS;
	  if ( resultStatus < 0 )
      {
        localManager = Object;
        otherResult = resultStatus;
        goto RELEASE_MUTEX;
      }
      KeReleaseMutex(Mutexa, 0);
      customManager = localResourceManager;
      Enlistment->ResourceManager = localResourceManager;
      otherEnlistment = (PKENLISTMENT)customManager;
      Mutexa = (PKMUTANT)&customManager->State;
      KeWaitForSingleObject(&customManager->State, 0, 0, 0, 0);
      localEnlistment = otherEnlistment;
    }
    localManager = Object;
  }
  refCount = localEnlistment->KeyRefCount;
  if ( refCount != 1 && refCount != 10 )
  {
    otherResult = 0xC0190003u;
    goto RELEASE_MUTEX;
  }
  if ( Uuid.Data2 & 1 )
  {
    if ( !localEnlistment->CrmEnlistmentEnId.Data2 )
    {
      Enlistment->State |= 1u;
      localEnlistment->CrmEnlistmentEnId.Data2 = (USHORT)Enlistment;
      goto LABEL_11;
    }
    otherResult = 0xC0190012u;
RELEASE_MUTEX:
    KeReleaseMutex(Mutexa, 0);
    ExFreePoolWithTag(localHandle, 0);
    MmQuitNextSession(localEnlistment);
    ObfDereferenceObject(localManager);
    return otherResult;
  }
LABEL_11:
  Enlistment->Transaction = (PKTRANSACTION)256;
  Enlistment->FinalNotification = 0;
  KeWaitForSingleObject(&localManager->Mutex, 0, 0, 0, 0);
  ++localManager->EnlistmentHead.Flink;
  listEntry = *(PLIST_ENTRY *)&localManager->NotificationMutex.Abandoned;
  Enlistment->NextSameTx.Blink = (struct _LIST_ENTRY *)&localManager->NotificationMutex.OwnerThread;
  Enlistment->NextSameRm.Flink = listEntry;
  listEntry->Flink = (LIST_ENTRY *)((char *)&Enlistment->NextSameTx + 4);

  if ( !(localManager->Flags & 4) )
  {
    ++localEnlistment->FinalNotification;
    Enlistment->State |= 2u;
  }
  ObfReferenceObject(Enlistment);
  if ( Enlistment->Flags & 2 )
	count = (int)(ULONGLONG)localEnlistment->SupSubEnlHandle;
    localEnlistment->SupSubEnlHandle = (PVOID)(ULONGLONG)(count + 1);
  if ( Enlistment->Flags & 1 )
    localEnlistment->SupSubEnlistment;
  compare = Enlistment->Flags;
  if ( compare & 4 && !(compare & 0x1000000) )
  {
	count = (int)(ULONGLONG)localEnlistment->SubordinateTxHandle;
    localEnlistment->SubordinateTxHandle = (PVOID)(ULONGLONG)(count+1);
    Enlistment->State |= 0x10u;
  }
  listEntry2 = (PLIST_ENTRY)&Enlistment->Mutex.Abandoned;
  listEntry3 = (PLIST_ENTRY)&localEnlistment->RecoveryInformationLength;
  if ( Enlistment->Flags & 0x200 )
  {
    Flink = listEntry3->Flink;
    listEntry2->Flink = listEntry3->Flink;
    Enlistment->NextSameTx.Flink = listEntry3;
    Flink->Blink = listEntry2;
    listEntry3->Flink = listEntry2;
  }
  else
  {
    listEntry4 = (PLIST_ENTRY)localEnlistment->DynamicNameInformation;
    listEntry2->Flink = listEntry3;
    Enlistment->NextSameTx.Flink = listEntry4;
    listEntry4->Flink = listEntry2;
    localEnlistment->DynamicNameInformation = listEntry2;
  }
  ++localEnlistment->DynamicNameInformationLength;
  ObfReferenceObject(Enlistment);
  ObfReferenceObject(Enlistment);
  if ( localManager->EnlistmentHead.Flink == (struct _LIST_ENTRY *)1 )
    TmpMakeResourceManagerPermanent(localManager);
  KeReleaseMutex(Mutexa, 0);
  KeReleaseMutex(&localManager->Mutex, 0);
  return 0;
}

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
)
{
  PKENLISTMENT handle; // edi@4
  NTSTATUS respInitialization; // esi@9
  NTSTATUS result; // eax@14
  PVOID OtherObject; // [sp+18h] [bp-3Ch]@10
  PHANDLE otherHandle; // [sp+1Ch] [bp-38h]@1
  PKENLISTMENT Object; // [sp+20h] [bp-34h]@3
  NTSTATUS results; // [sp+24h] [bp-30h]@3
  UUID Uuid; // [sp+28h] [bp-2Ch]@7
  CPPEH_RECORD ms_exc; // [sp+3Ch] [bp-18h]@19

  otherHandle = EnlistmentHandle;
  if ( CreateOptions > 3 || NotificationMask & 0xFE000000 )
  {
    result = 0xC000000Du;
  }
  else
  {
    results = ObCreateObject(
                PreviousMode,
                TmEnlistmentObjectType,
                ObjectAttributes,
                PreviousMode,
                0,
                320,
                0,
                0,
                &Object);
    if ( results < 0 )
      return results;
    handle = Object;
    Object->Transaction = 0;
    ExUuidCreate(&Uuid);
    if ( results < 0 )
    {
DeferenceObject:
      ObfDereferenceObject(handle);
      return results;
    }
    respInitialization = TmInitializeEnlistment(
                           handle,
                           ResourceManager,
                           Transaction,
                           Uuid,
                           CreateOptions,
                           NotificationMask,
                           EnlistmentKey);
    if ( respInitialization >= 0 )
    {
      ObfReferenceObject(handle);
      results = ObInsertObject(handle, 0, DesiredAccess, 0, 0, &OtherObject);
      if ( results < 0 )
      {
        TmEnlistmentObjectType->TypeInfo.CloseProcedure(0, handle, 0, 1u, 1u);
      }
      else
      {
        if ( PreviousMode )
        {
          *otherHandle = OtherObject;
          ms_exc.registration.TryLevel = -2;
        }
        else
        {
          *otherHandle = OtherObject;
        }
      }
      goto DeferenceObject;
    }
    ObfDereferenceObject(handle);
    result = respInitialization;
  }
  return result;
}

int TmCreateResourceManagerWithCallbacks(PHANDLE handle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES a3, char a4, DWORD a5, DWORD a6)
{
  int v6; // ST34_4@1
  PVOID v7; // esi@1
  PHANDLE localHandle = NULL; // [sp+1Ch] [bp-24h]@2
  PVOID v10 = NULL; // [sp+20h] [bp-20h]@1
  int v11; // [sp+24h] [bp-1Ch]@1
  CPPEH_RECORD ms_exc = {0, NULL, NULL}; // [sp+28h] [bp-18h]@1

  ms_exc.registration.TryLevel = 0;
  v6 = ObCreateObject(0, resource, a3, 0, 0, 184, 0, 0, v10);
  v7 = v10;
  v11 = v6;
  if ( v6 >= 0 )
  {
    //TmInitializeResourceManager(v10, 0, a4, a5, a6);
    v7 = NULL;
    v11 = ObInsertObject(v7, 0, AccessMask, 0, 0, localHandle);
    if ( v11 >= 0 )
    {
      *handle = localHandle;
      ms_exc.registration.TryLevel = 0;
    }
  }
  return v11;
}

void GetVirtualClock(PLIST_ENTRY Flink, PLARGE_INTEGER TmVirtualClock)
{
  if ( TmVirtualClock )
  {
    ExAcquireFastMutex((PFAST_MUTEX)&Flink[23]);
#if defined(_i386_)
    if ( (ULONG)TmVirtualClock->LowPart > (ULONG)Flink[22].Flink )
	{
      Flink[22].Flink = (struct _LIST_ENTRY *)TmVirtualClock->LowPart;
      Flink[22].Blink = (struct _LIST_ENTRY *)TmVirtualClock->HighPart;	
#else
    if ( (ULONGLONG)TmVirtualClock->LowPart > (ULONGLONG)Flink[22].Flink )
	{
      Flink[22].Flink = (struct _LIST_ENTRY *)(ULONGLONG)TmVirtualClock->LowPart;
      Flink[22].Blink = (struct _LIST_ENTRY *)(ULONGLONG)TmVirtualClock->HighPart;
#endif
    }
    ExReleaseFastMutex((PFAST_MUTEX)&Flink[23]);
  }
}

int ResourceHelper(PKRESOURCEMANAGER a1)
{
  PLIST_ENTRY list; // ecx@3
  PKTHREAD v2; // eax@3
#if defined(_i386_)
  if ( (ULONG)a1->NotificationQueue.EntryListHead.Blink & 0x20 )
  {
    KeWaitForSingleObject((PKTHREAD)a1->Enlistments.Expired, 0, 0, 0, 0);
    if ( (ULONG)a1->NotificationQueue.EntryListHead.Blink & 0x20 )
#else
  if ( (ULONGLONG)a1->NotificationQueue.EntryListHead.Blink & 0x20 )
  {
    KeWaitForSingleObject((PKTHREAD)a1->Enlistments.Expired, 0, 0, 0, 0);
    if ( (ULONGLONG)a1->NotificationQueue.EntryListHead.Blink & 0x20 )
#endif
    {
      list = a1->Enlistments.Mutex.MutantListEntry.Blink;
      v2 = a1->Enlistments.Mutex.OwnerThread;
      v2 = (PKTHREAD)list;
      list->Blink = (struct _LIST_ENTRY *)v2;
#if defined(_i386_)
      a1->NotificationQueue.EntryListHead.Blink = (struct _LIST_ENTRY *)((ULONG)a1->NotificationQueue.EntryListHead.Blink & 0xFFFFFFDF);
#else
      a1->NotificationQueue.EntryListHead.Blink = (struct _LIST_ENTRY *)((ULONGLONG)a1->NotificationQueue.EntryListHead.Blink &0xFFFFFFDF);
#endif
      a1->NotificationMutex.MutantListEntry.Blink = 0;
      a1->NotificationMutex.OwnerThread = 0;
    }
    KeReleaseMutex((PRKMUTEX)a1->Enlistments.Expired , 0);
  }
  a1->NotificationQueue.EntryListHead.Flink = (struct _LIST_ENTRY *)10;
  ObMakeTemporaryObject(a1);
  TmDereferenceResourceManager(a1);
  return 0;
}

//unimplemented //update
NTSTATUS TmCommitComplete(
  IN  PKENLISTMENT Enlistment,
  IN  PLARGE_INTEGER TmVirtualClock
)
{
  PKENLISTMENT localEnlistment; // esi@1
  PKRESOURCEMANAGER localResourceManager; // edi@1
  PKTRANSACTION transaction; // ecx@1
  BOOLEAN verification; // zf@2
  NTSTATUS receive; // esi@3
  PKMUTANT otherMutex; // eax@11
  PKMUTANT oneMutex; // [sp+Ch] [bp-4h]@1
  BOOLEAN other; // [sp+1Bh] [bp+Bh]@5
  PKMUTANT Mutexa; // [sp+1Ch] [bp+Ch]@1

  localEnlistment = Enlistment;
  localResourceManager = Enlistment->ResourceManager;
  DbgPrintEx(107, 0x80000020u, "KTM:  TmCommitComplete for tx %lx\n", (char)Enlistment->ResourceManager);
  GetVirtualClock(Enlistment->NextSameRm.Blink[23].Flink, TmVirtualClock);
  oneMutex = (PKMUTANT)&localResourceManager->State;
  KeWaitForSingleObject(&localResourceManager->State, 0, 0, 0, 0);
  Mutexa = (PKMUTANT)&Enlistment->EnlistmentId.Data4[4];
  KeWaitForSingleObject(&Enlistment->EnlistmentId.Data4[4], 0, 0, 0, 0);
  transaction = Enlistment->Transaction;
  if ( transaction == (PKTRANSACTION)261 )
  {
    verification = 0;
  }
  else
  {
    verification = transaction == (PKTRANSACTION)263;
    if ( transaction != (PKTRANSACTION)263 )
    {
      KeReleaseMutex(Mutexa, 0);
      receive = 0xC0190014u;
LABEL_7:
      KeReleaseMutex(oneMutex, 0);
      return receive;
    }
  }
  other = verification;
  localEnlistment->Transaction = (PKTRANSACTION)260;
  //sub_614488(localEnlistment);
  --localEnlistment->ResourceManager->NotificationMutex.Header.WaitListHead.Flink;
  KeReleaseMutex(Mutexa, 0);
  if ( localResourceManager->NotificationMutex.Header.WaitListHead.Flink > 0 )
  {
    receive = 0;
    goto LABEL_7;
  }
  if ( other )
  {
    localResourceManager->NotificationQueue.EntryListHead.Flink = (struct _LIST_ENTRY *)5;
    localResourceManager->Enlistments.Mutex.Abandoned = 2;
    KeSetEvent(&localResourceManager->NotificationAvailable, 0, 0);
    localEnlistment->Flags &= 0xFFFFFFFBu;
    //sub_614C77(localResourceManager, 4, 1, 261, 0, 0);
  }
  else
  {
    ;//sub_616A78(localResourceManager, 4, 0);
  }
  otherMutex = (PKMUTANT)localResourceManager->NotificationMutex.Header.WaitListHead.Blink;
  if ( otherMutex )
    ;//sub_614B88(otherMutex, 1, 64, 1, 260, 0, 0);
  ObfReferenceObject(localResourceManager);
  ResourceHelper(localResourceManager);
  KeReleaseMutex(oneMutex, 0);
  ObfDereferenceObject(localResourceManager);
  return 0;
}

//unimplemented
NTSTATUS NTAPI TmDefaultTmOpenFileCount(PHANDLE handle)
{
	return 0x00000000;
}

void MutexHelper(PVOID hum)
{
	 if ( hum )
  {
    ExAcquireFastMutex(mutant);
    if ( *(QWORD *)hum > helper )
      helper = *(QWORD *)hum;
    ExReleaseFastMutex(mutant);
  }
}

NTSTATUS NTAPI TmEnableCallbacksHelper(PRKEVENT event, DWORD verification, DWORD a3, PLIST_ENTRY a4, PLIST_ENTRY a5, SIZE_T a6, const void *a7)
{
  PVOID fisrt; // esi@1
  PVOID other; // edi@1
  PLIST_ENTRY list; // ecx@1
  int (__stdcall *v10)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // edx@3
  NTSTATUS temp; // esi@8
  NTSTATUS result; // eax@12
  PVOID *receive; // eax@13
  PVOID compose; // ebx@13
  PVOID hum; // [sp+Ch] [bp-2Ch]@1
  PVOID error; // [sp+10h] [bp-28h]@1
  PVOID number; // [sp+18h] [bp-20h]@1
  NTSTATUS status; // [sp+1Ch] [bp-1Ch]@1
  CPPEH_RECORD ms_exc; // [sp+20h] [bp-18h]@5

  number = 0;
  status = 0;
  ExAcquireFastMutex(mutant);
  hum = globalHum;
  error = globalSecond;
  ExReleaseFastMutex(mutant);
  fisrt = hum;
  other = error;
  list = event[1].Header.WaitListHead.Flink;
  if ( (unsigned __int8)list & 2 )
    a4 = 0;
  v10 = *(int (__stdcall **)(PRKEVENT, DWORD, DWORD, PLIST_ENTRY, PLIST_ENTRY, SIZE_T, DWORD))&event[10].Header.Type;
  if ( !v10 || (unsigned __int8)list & 1 )
  {
    status = 259;
    receive = (PVOID *)ExAllocatePoolWithQuotaTag(0, a6 + 32, 0x6F4E6D54u);
    compose = receive;
    number = receive;
    ms_exc.registration.TryLevel = -1;
    if ( receive )
    {
      receive[2] = a4;
      receive[3] = a5;
      receive[4] = hum;
      receive[5] = error;
      receive[6] = (PVOID)a6;
      memcpy(receive + 8, a7, a6);
      KeWaitForSingleObject(&event[7].Header.SignalState, 0, 0, 0, 0);
      KeInsertQueue((PRKQUEUE)event[4].Header.WaitListHead.Blink, compose);
      KeSetEvent(event, 0, 0);
      KeReleaseMutex((PRKMUTEX)&event[7].Header.SignalState, 0);
    }
    else
    {
      status = 0xC000009Au;
    }
    result = status;
  }
  else
  {
    ms_exc.registration.TryLevel = 0;
    status = v10(a3, event[10].Header.SignalState, a4, a5, &hum, a6, a7);
    if ( fisrt != hum || other != error )
      MutexHelper(hum);
    ms_exc.registration.TryLevel = -1;
    temp = status;
    if ( status != 259 && status )
    {
      if ( status != 0xC0190003 )
        DbgPrint("KTM:  buggy RM returned status %x in response to %x\n", status);
    }
    result = temp;
  }
  return result;
}

  //Review
NTSTATUS NTAPI TmEnableCallbacks(PKEVENT Event)
{

  /*PKEVENT localEvent; // edi@1
  PLIST_ENTRY list; // esi@3
  NTSTATUS resp; // eax@4
  NTSTATUS result; // eax@5
  PKMUTANT Mutex; // [sp+8h] [bp-Ch]@3
  struct _LIST_ENTRY *entry; // [sp+Ch] [bp-8h]@3
  NTSTATUS status; // [sp+10h] [bp-4h]@1
  PVOID Eventa; // [sp+1Ch] [bp+8h]@4

  localEvent = Event;
  status = 0;
  if ( *(DWORD *)&Event[10].Header.Type && (unsigned int)Event[1].Header.WaitListHead.Flink & 1 )
  {
    Mutex = (PKMUTANT)&Event[1].Header.WaitListHead.Blink;
    KeWaitForSingleObject(&Event[1].Header.WaitListHead.Blink, 0, 0, 0, 0);
    Event[1].Header.WaitListHead.Flink = (struct _LIST_ENTRY *)((unsigned int)Event[1].Header.WaitListHead.Flink & 0xFFFFFFFE);
    list = (PLIST_ENTRY)KeRundownQueue((PRKQUEUE)Event[4].Header.WaitListHead.Blink);
    entry = list;
    if ( list )
    {
      do
      {
        Eventa = list;
        resp = TmEnableCallbacksHelper(
                 localEvent,
                 0,
                 0,
                 list[1].Flink,
                 list[1].Blink,
                 (unsigned int)list[3].Flink,
                 (const void *)(list[3].Flink != 0 ? (int)&list[4] : 0));
        list = list->Flink;
        status = resp;
        ExFreePoolWithTag(Eventa, 0);
      }
      while ( entry != list );
    }
    KeInitializeQueue((PRKQUEUE)localEvent[4].Header.WaitListHead.Blink, 0);
    KeResetEvent(localEvent);
    KeReleaseMutex(Mutex, 0);
    result = status;
  }
  else
  {
    result = 0xC0000001u;
  }
  return result;*/
  return 0x00000000;
}

void NTAPI TmRollbackEnlistmentHelper(PLIST_ENTRY eliment, PLARGE_INTEGER number)
{
  PFAST_MUTEX receive; // esi@1

  receive = (PFAST_MUTEX)eliment[1].Flink;
#if defined(_i386_)
  ExAcquireFastMutex((PFAST_MUTEX)receive[7].Contention);
#else
  ExAcquireFastMutex((PFAST_MUTEX)(ULONGLONG)receive[7].Contention);
#endif
  if ( &number->LowPart > &receive[7].Count )
  {
    receive[7].Count = number->LowPart;
#if defined(_i386_)
    receive[7].Owner = (PKTHREAD)number->HighPart;
#else
    receive[7].Owner = (PKTHREAD)(ULONGLONG)number->HighPart;
#endif
  }
#if defined(_i386_)
  ExReleaseFastMutex((PFAST_MUTEX)receive[7].Contention);
#else
  ExReleaseFastMutex((PFAST_MUTEX)(ULONGLONG)receive[7].Contention);
#endif
}

//Review
LONG NTAPI TmRollbackEnlistment(PKENLISTMENT Enlistment, PLARGE_INTEGER TmVirtualClock)
{
  
  PVOID *resource; // esi@1
  PKTRANSACTION transaction; // eax@2
  PVOID otherResource; // eax@13
  PVOID receive; // eax@20
  BOOLEAN verification; // [sp+16h] [bp-1Ah]@1
  BOOLEAN annotation; // [sp+17h] [bp-19h]@1

  resource = (PVOID *)Enlistment->ResourceManager;
  DbgPrintEx(108, -2147483616, "KTM:  TmRollbackEnlistment for tx %lx\n", Enlistment->ResourceManager);
  TmRollbackEnlistmentHelper(Enlistment->NextSameRm.Blink[23].Flink, TmVirtualClock);
  KeWaitForSingleObject(resource + 5, 0, 0, 0, 0);
  KeWaitForSingleObject(&Enlistment->EnlistmentId.Data4[4], 0, 0, 0, 0);
  verification = 1;
  annotation = 0;
  if ( Enlistment->State & 1 )
  {
    otherResource = resource[25];
    if ( otherResource == (PVOID)1
      || otherResource == (PVOID)2
      || otherResource == (PVOID)8
      || otherResource == (PVOID)4
      || otherResource == (PVOID)3
      || otherResource == (PVOID)12
      || otherResource == (PVOID)11 )
    {
      annotation = 1;
      receive = resource[26];
      if ( !((unsigned __int8)receive & 0x10) )
#if defined(_i386_)
        resource[26] = (PVOID)((ULONG)receive | 8);
#else
        resource[26] = (PVOID)((ULONGLONG)receive | 8);
#endif
    }
  }
  else
  {
    transaction = Enlistment->Transaction;
    if ( transaction == (PKTRANSACTION)256
      || transaction == (PKTRANSACTION)257
      || transaction == (PKTRANSACTION)265
      || transaction == (PKTRANSACTION)273
      || transaction == (PKTRANSACTION)263
      || transaction == (PKTRANSACTION)268 )
      annotation = 1;
  }
  if ( annotation )
  {
    KeReleaseMutex((PRKMUTEX)&Enlistment->EnlistmentId.Data4[4], 0);
    verification = 0;
    //sub_62CC3F((PRKEVENT)resource); //review
  }
  if ( verification )
    KeReleaseMutex((PRKMUTEX)&Enlistment->EnlistmentId.Data4[4], 0);
  return KeReleaseMutex((PRKMUTEX)(resource + 5), 0);
}

//unimplemented
NTSTATUS NTAPI TmPrepareComplete(
  IN  PKENLISTMENT Enlistment,
  IN  PLARGE_INTEGER TmVirtualClock
)
{
	return 0x00000000;
}

//unimplemented
NTSTATUS NTAPI TmPrePrepareComplete(
  IN  PKENLISTMENT Enlistment,
  IN  PLARGE_INTEGER TmVirtualClock
)
{
	return 0x00000000;
}

//unimplemented
NTSTATUS NTAPI TmReadOnlyEnlistment(
  IN  PKENLISTMENT Enlistment,
  IN  PLARGE_INTEGER TmVirtualClock
)
{
	return 0x00000000;
}

//unimplemented
NTSTATUS NTAPI TmRollbackComplete(
  IN  PKENLISTMENT Enlistment,
  IN  PLARGE_INTEGER TmVirtualClock
)
{
	return 0x00000000;
}

NTSTATUS NTAPI NtReferenceEnlistmentKey(HANDLE Handle, PVOID Object)
{
  PVOID localObject; // esi@1
  NTSTATUS result; // eax@2
  KPROCESSOR_MODE mode; // bl@3
  struct _KMUTANT Mutex; // [sp+14h] [bp-1Ch]@4
  NTSTATUS Handlea; // [sp+38h] [bp+8h]@5

  localObject = Object;
  if ( Object )
  {
	mode = KeGetPreviousMode();
    if ( mode )
    {
      ProbeForWrite(Object, 4, 4);
      Mutex.OwnerThread = (PKTHREAD)-1;
    }
    Handlea = ObReferenceObjectByHandle(Handle, 8, TmEnlistmentObjectType, mode, &Object, 0);
    if ( Handlea >= 0 )
    {
      Handlea = TmReferenceEnlistmentKey(Object, &Mutex);
      ObfDereferenceObject(Object);
      if ( mode )
      {
        localObject = &Mutex;
        Mutex.OwnerThread = (PKTHREAD)-1;
      }
      else
      {
        localObject = &Mutex;
      }
    }
    result = Handlea;
  }
  else
  {
    result = STATUS_SUCCESS;
  }
  return result;
}

void TmpCheckForNullAccessOpen(ACCESS_MASK mask)
{
    if ( !mask )
    {
      DbgPrintEx(
        106,
        0,
        "KTM: ** This break is occuring because a handle is being opened for no access.\nKTM: ** KTM\\Parameters\\BreakOnNullDesiredAccessOpens was non-zero on bootup.\nKTM: ** You can turn this breakpoint off by either setting that key to zero or\nKTM: **     in the debugger by setting nt!TmpBreakOnNullDesiredAccessOpens to zero.\n");
      DbgBreakPoint();
  }
}

NTSTATUS NTAPI NtCreateEnlistment(
	PHANDLE EnlistmentHandle, 
	ACCESS_MASK DesiredAccess, 
	HANDLE ResourceManagerHandle, 
	HANDLE TransactionHandle, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	ULONG CreateOptions, 
	NOTIFICATION_MASK NotificationMask, 
	PVOID EnlistmentKey)
{
  NTSTATUS status; // esi@2
  HANDLE localHandle; // ecx@7
  PVOID Object; // [sp+14h] [bp-24h]@2
  HANDLE otherHandle; // [sp+18h] [bp-20h]@3
  KPROCESSOR_MODE AccessMode; // [sp+1Ch] [bp-1Ch]@1
  CPPEH_RECORD ms_exc; // [sp+20h] [bp-18h]@7

  TmpCheckForNullAccessOpen(DesiredAccess);
  AccessMode = KeGetPreviousMode();
  if ( AccessMode )
  {
    ms_exc.registration.TryLevel = 0;
    localHandle = EnlistmentHandle;
    if ( EnlistmentHandle >= (PHANDLE)MmUserProbeAddress )
      localHandle = (PHANDLE)MmUserProbeAddress;
    ms_exc.registration.TryLevel = -1;
  }
  status = ObReferenceObjectByHandle(TransactionHandle, 8, TmResourceManagerObjectType, AccessMode, &Object, 0);
  if ( status >= 0 )
  {
    status = ObReferenceObjectByHandle(ObjectAttributes, 4, TmTransactionObjectType, AccessMode, &otherHandle, 0);
    if ( status >= 0 )
    {
      status = TmCreateEnlistment(
                 EnlistmentHandle,
                 AccessMode,
                 DesiredAccess,
                 ResourceManagerHandle,
                 Object,
                 otherHandle,
                 CreateOptions,
                 NotificationMask,
                 EnlistmentKey);
      ObfDereferenceObject(otherHandle);
    }
    ObfDereferenceObject(Object);
  }
  return status;
}