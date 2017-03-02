/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    iolongfuncs.c

Abstract:

    This module contains the code to implement the NtOpenFile system
    service.

--*/

#include "iolongfuncs.h"

#pragma alloc_text(PAGE, NtRemoveIoCompletionEx)
#pragma alloc_text(PAGE, NtCreateIoCompletionEx)

PVOID MmBadPointer = 0;

typedef struct _ECP_LIST * PECP_LIST;

typedef unsigned short USHORTP;

VOID NTAPI IoDisconnectInterruptEx(
  PIO_DISCONNECT_INTERRUPT_PARAMETERS Parameters
)
{
	IoDisconnectInterrupt(Parameters->ConnectionContext.InterruptObject);	
}

NTSTATUS NTAPI IoConnectInterruptEx(
  PIO_CONNECT_INTERRUPT_PARAMETERS Parameters
)
{
  BOOLEAN (__stdcall *function)(struct _KINTERRUPT *, PVOID); // edi@3
  KIRQL otherIRQ; // al@4
  KIRQL localIRQ; // cl@4
  NTSTATUS result; // eax@5

  if ( Parameters->Version == 1 )
  {
    if ( Parameters->FullySpecified.PhysicalDeviceObject
      && (function = Parameters->FullySpecified.ServiceRoutine) != 0
      && (otherIRQ = Parameters->FullySpecified.SynchronizeIrql,
          localIRQ = Parameters->FullySpecified.Irql,
          otherIRQ >= localIRQ) )
      result = IoConnectInterrupt(
                 Parameters->FullySpecified.InterruptObject,
                 function,
                 Parameters->FullySpecified.ServiceContext,
                 Parameters->FullySpecified.SpinLock,
                 Parameters->FullySpecified.Vector,
                 localIRQ,
                 otherIRQ,
                 Parameters->FullySpecified.InterruptMode,
                 Parameters->FullySpecified.ShareVector,
                 Parameters->FullySpecified.ProcessorEnableMask,
                 Parameters->FullySpecified.FloatingSave);
    else
      result = 0xC000000Du;
  }
  return result;
}

//unimplemented
int NTAPI IoGetSfioPriorityHint(PVOID parameters)
{
	return 1;
}

//unimplemented
PVOID NTAPI IoGetSfioStreamIdentifier(IN PFILE_OBJECT FileObject, IN PVOID  Signature) 
{
	return 0;
}	

NTSTATUS NTAPI IoAllocateSfioStreamIdentifier(PFILE_OBJECT FileObject, ULONG Length, PVOID Signature, PVOID *StreamIdentifier)
{
  NTSTATUS result; // eax@2

  if ( FileObject )
  {
    if ( Length )
    {
      if ( Signature )
        //result = sub_43EB3E(FileObject, Length, Signature, StreamIdentifier, 1);
		;
      else
        result = 0xC00000F1u;
    }
    else
    {
      result = 0xC00000F0u;
    }
  }
  else
  {
    result = 0xC00000EFu;
  }
  return result;
}

//unimplemented
IO_PRIORITY_HINT IoGetIoPriorityHint(
  IN PIRP Irp
)
{
	return 1;
}

NTSTATUS IoGetIrpExtraCreateParameter(PIRP Irp, PECP_LIST ExtraCreateParameter)
{
  NTSTATUS result; // eax@2

  if ( Irp->Tail.Overlay.CurrentStackLocation )
  {
    result = 0xC000000Du;
  }
  else
  {
    ExtraCreateParameter = Irp->UserBuffer;
    result = 0;
  }
  return result;
}

PFILE_OBJECT NTAPI IoGetAvioFileObjectFromIrp(PIRP irp)
{
  PIRP localIRP; // eax@1

  localIRP = irp;
  if ( irp->Flags & 8 )
    localIRP = irp->AssociatedIrp.MasterIrp;
  return localIRP->Tail.Overlay.OriginalFileObject;
}

//maybe unimplemented
BOOLEAN NTAPI IoGetAvioStreamContext(KIRQL NewIrql, int a2, PFILE_OBJECT a3, int a4)
{
  PFILE_OBJECT fileLocal = NULL; // eax@1
  PFILE_OBJECT fileObject; // ebx@1
  BOOLEAN result; // al@6
  KSPIN_LOCK *SpinLock; // [sp+4h] [bp-4h]@2
  KIRQL irql; // [sp+13h] [bp+Bh]@2

  fileObject = fileLocal;
  if ( fileLocal )
  {
    SpinLock = (KSPIN_LOCK *)&fileLocal->Lock.Header.SignalState;
#if defined(_i386_)
		irql = KfAcquireSpinLock((PKSPIN_LOCK)(DWORD64)&fileLocal->Lock.Header.SignalState);
#else
		irql = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(DWORD64)&fileLocal->Lock.Header.SignalState);
#endif	
    if ( a3 )
    {
      *(DWORD *)&a3->Type = fileObject->CurrentByteOffset.LowPart;
      a3->DeviceObject = (PDEVICE_OBJECT)(DWORD64)fileObject->CurrentByteOffset.HighPart;
      a3->Vpb = (PVPB)(DWORD64)fileObject->Waiters;
      a3->FsContext = (PVOID)(DWORD64)fileObject->Busy;
    }
#if defined(_x86_)
    KfReleaseSpinLock(SpinLock, irql);
#else
	ExReleaseSpinLock(SpinLock, irql);
#endif	
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}

//need urgent rewrite!
int NTAPI IoAllocateAvioStreamDriverContext(int a1, int a2, int a3)
{
  int v3= 1; // edi@1
  PVOID v4; // eax@4
  PVOID v5; // esi@4
  char v6 = 1; // al@5
  KSPIN_LOCK *v8; // ebx@9
  KIRQL v9; // al@9
  int v10; // ecx@9
  int v11; // edi@9

  if ( !v3 )
    v3 = *(DWORD *)(DWORD64)(a1 + 84);
  if ( TRUE )
  {
    v5 = ExAllocatePoolWithTagPriority(0, a3 + 16, 0x20206F49u, (EX_POOL_PRIORITY)(v6 != 0 ? 40 : 32));
    if ( !v5 )
      ExRaiseStatus(-1073741670);
  }
  else
  {
    v4 = ExAllocatePoolWithQuotaTag(0, a3 + 16, 0x20206F49u);
    v5 = v4;
    if ( !v4 )
      return 0;
  }
  v8 = (KSPIN_LOCK *)(DWORD64)(v3 + 80);
  *((DWORD *)v5 + 2) = a2;
#if defined(_i386_)
  v9 = KfAcquireSpinLock((PKSPIN_LOCK)(DWORD64)(v3 + 80));
#else
  v9 = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(DWORD64)(v3 + 80));
#endif
  v10 = v3 + 72;
  v11 = *(DWORD *)(DWORD64)(v3 + 76);
  *(DWORD *)v5 = v10;
  *((DWORD *)v5 + 1) = v11;
  v11 = (DWORD)(DWORD64)v5;
  v10 = (DWORD)(DWORD64)v5;
#if defined(_i386_)
  KfReleaseSpinLock(v8, v9);
#else
  ExReleaseSpinLock(v8, v9);
#endif
  return (int)(DWORD64)((char *)v5 + 12);
}
NTSTATUS NTAPI IoSetIoCompletionEx(
		IN PVOID  	IoCompletion,
		IN PVOID  	KeyContext,
		IN PVOID  	ApcContext,
		IN NTSTATUS  	IoStatus,
		IN ULONG_PTR  	IoStatusInformation,
		IN BOOLEAN  	Quota, 
		IN DWORD		Verification
	) 	
{
	return IoSetIoCompletion(IoCompletion, KeyContext, ApcContext, IoStatus, IoStatusInformation, Quota);
}

PTXN_PARAMETER_BLOCK NTAPI IoGetTransactionParameterBlock(
  IN  PFILE_OBJECT FileObject
)
{
	return NULL;
}

NTSTATUS NTAPI IoSetDevicePropertyData(PDEVICE_OBJECT BugCheckParameter2, const DEVPROPKEY *PropertyKey, int a3, ULONG a4, DEVPROPKEY Data, ULONG DataSize, PVOID Data_8)
{
  int v7; // eax@2

  if ( !BugCheckParameter2
    || (v7 = *((DWORD *)BugCheckParameter2->DeviceObjectExtension + 5)) == 0
    || *(DWORD *)(DWORD64)(v7 + 140) & 0x20000 )
    KeBugCheckEx(0xCAu, 2u, (ULONG_PTR)BugCheckParameter2, 0, 0);
  //return IoSetDevicePropertyDataHelper(BugCheckParameter2, a3, a4, Data.fmtid.Data1, DataSize, Data_8);
  return 0x00000000;
}

void NTAPI IoQueueWorkItemEx(PWORK_QUEUE_ITEM WorkItem, struct _LIST_ENTRY *list, WORK_QUEUE_TYPE QueueType, PVOID a4)
{
  ObfReferenceObject(WorkItem[1].List.Blink);
  WorkItem[1].List.Flink = list;
  WorkItem[1].WorkerRoutine = (PWORKER_THREAD_ROUTINE)a4;
  ExQueueWorkItem(WorkItem, QueueType);
}

ULONG NTAPI IoSizeofWorkItem()
{
  return 32;
}

//need current implementation (vista newer builds)
ULONG_PTR NTAPI IoUninitializeWorkItem(ULONG_PTR BugCheckParameter2)
{
  ULONG_PTR result; // eax@1

  result = BugCheckParameter2;
  if ( *(DWORD *)BugCheckParameter2 )
    KeBugCheckEx(0xE4u, 2u, BugCheckParameter2, BugCheckParameter2 + 16, 0);
  return result;
}

NTSTATUS NTAPI IoFreeSfioStreamIdentifier(PFILE_OBJECT NewIrql, PVOID Signature)
{
  PVOID *v2 = NULL; // esi@1
  NTSTATUS status; // ebx@1
  KSPIN_LOCK *spin; // edi@2
  PVOID *count; // eax@2
  PVOID other; // ecx@7
  PVOID *unknown; // edx@7
  KIRQL irq; // [sp+17h] [bp+Bh]@2

  status = 0xC0000225u;
  if ( v2 )
  {
    spin = (KSPIN_LOCK *)&NewIrql[1];
#if defined(_i386_)
    irq = KfAcquireSpinLock((PKSPIN_LOCK)&NewIrql[1]);
#else
	irq = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)&NewIrql[1]);
#endif
    for ( count = (PVOID *)*v2; count != v2; count = (PVOID *)*count )
    {
      if ( count[3] == Signature )
      {
        other = *count;
        unknown = (PVOID *)count[1];
        status = 0;
        *unknown = *count;
        other = unknown;
        ExFreePoolWithTag(count, 0);
        break;
      }
    }
#if defined(_i386_)
    KfReleaseSpinLock(spin, irq);
#else
	ExReleaseSpinLock(spin, irq);
#endif
  }
  return status;
}

VOID NTAPI IoInitializeWorkItem(
  IN  PVOID IoObject,
  IN  PIO_WORKITEM IoWorkItem
)
{
	IoWorkItem = NULL;
}

NTSTATUS NTAPI IoGetActivityIdIrp(PIRP Irp, LPGUID Guid)
{
  PVOID apc; // esi@1
  PIRP irpLocal; // esi@3
  NTSTATUS result; // eax@3

  apc = Irp->Tail.Apc.SystemArgument2;
  if (apc && *((BYTE *)apc + 4) & 1 )
  {
    irpLocal = (PIRP)(apc);
    Guid->Data1 = *&irpLocal->Type;
    irpLocal = (irpLocal + 4);
    *&Guid->Data2 = *&irpLocal->Type;
    irpLocal = (irpLocal + 4);
    Guid->Data4[0] = (unsigned char)irpLocal->Type;
    Guid->Data4[4] = (unsigned char)irpLocal->MdlAddress;
    result = 0;
  }
  else
  {
    result = 0xC0000225u;
  }
  return result;
}

NTSTATUS NTAPI IoSetActivityIdIrp(PIRP Irp, LPGUID Guid)
{
  LPGUID localGuid; // ecx@1
  NTSTATUS status; // ebx@1
  NTSTATUS result; // eax@2
  PVOID compose; // ecx@9
  BOOLEAN verification; // zf@10

  localGuid = (LPGUID)Irp->Tail.Apc.SystemArgument2;
  status = 0;
  if ( localGuid )
  {
    localGuid->Data2 |= 1u;
    if ( Guid )
    {
      localGuid->Data4[0] = (unsigned char)Guid->Data1;
      localGuid->Data4[4] = (unsigned char)Guid->Data2;
      localGuid[1].Data1 = *&Guid->Data4[0];
      *&localGuid[1].Data2 = *&Guid->Data4[4];
    }
    else
    {
#if defined(_i386_)
     if ( (PETHREAD)__readfsdword(292) == Irp->Tail.Overlay.Thread )
#else
	if ( (PETHREAD)__readgsqword(292) == Irp->Tail.Overlay.Thread )
#endif	  
        status = 0x00000000;//EtwActivityIdControl(1, localGuid->Data4); Tem que fazer e colocar em um header
      else
        status = 0xC00000BBu;
      if ( status < 0 )
      {
        compose = Irp->Tail.Apc.SystemArgument2;
        if ( compose )
        {
          verification = (*((WORD *)compose + 2) & 0xFFFE) == 0;
          *((WORD *)compose + 2) &= 0xFFFEu;
          if ( verification )
          {
            if ( *(BYTE *)compose & 1 )
            {
              ExFreePoolWithTag(compose, 0x58707249u);
              Irp->Tail.Apc.SystemArgument2 = 0;
            }
          }
        }
      }
    }
    result = status;
  }
  else
  {
    result = 0xC0000001u;
  }
  return result;
}

NTSTATUS NTAPI IoSetIoPriorityHint(PIRP Irp, IO_PRIORITY_HINT PriorityHint)
{
  NTSTATUS result; // eax@2

  if ( (signed int)PriorityHint <= 5 )
  {
    Irp->Flags = Irp->Flags & 0xFFF1FFFF | ((PriorityHint + 1) << 17);
    result = 0;
  }
  else
  {
    result = 0xC000000Du;
  }
  return result;
}

NTSTATUS NTAPI IoCreateFileEx(
  OUT     PHANDLE FileHandle,
  IN      ACCESS_MASK DesiredAccess,
  IN      POBJECT_ATTRIBUTES ObjectAttributes,
  OUT     PIO_STATUS_BLOCK IoStatusBlock,
  IN 	  PLARGE_INTEGER AllocationSize,
  IN      ULONG FileAttributes,
  IN      ULONG ShareAccess,
  IN      ULONG Disposition,
  IN      ULONG CreateOptions,
  IN  	  PVOID EaBuffer,
  IN      ULONG EaLength,
  IN      CREATE_FILE_TYPE CreateFileType,
  IN  	  PVOID InternalParameters,
  IN      ULONG Options,
  IN  	  PIO_DRIVER_CREATE_CONTEXT DriverContext
)
{
	return IoCreateFile(FileHandle, 
						DesiredAccess, 
						ObjectAttributes, 
						IoStatusBlock, 
						AllocationSize, 
						FileAttributes, 
						ShareAccess, 
						Disposition,
						CreateOptions,
						EaBuffer,
						EaLength,
						CreateFileType,
						InternalParameters,
						Options);
}

NTSTATUS NTAPI IoRequestDeviceEjectEx(
  IN PDEVICE_OBJECT PhysicalDeviceObject,
  IN PIO_DEVICE_EJECT_CALLBACK Callback OPTIONAL,
  IN PVOID Context OPTIONAL,
  IN PDRIVER_OBJECT DriverObject OPTIONAL)
{
	IoRequestDeviceEject(PhysicalDeviceObject);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtRemoveIoCompletionEx(
	__in HANDLE IoCompletionHandle,
	__out_ecount(Count) PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	__in ULONG  	Count,
	__out PULONG  	NumEntriesRemoved,
	__in_opt PLARGE_INTEGER  	Timeout,
	__in BOOLEAN  	Alertable 
)
{
	return NtRemoveIoCompletion(IoCompletionHandle, 0, 0, NULL, Timeout);
}

NTSTATUS NTAPI NtCreateIoCompletionEx(
	__out PHANDLE IoCompletionHandle, 
	__in ACCESS_MASK DesiredAccess, 
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes, 
	__in_opt ULONG Count
)
{
	return NtCreateIoCompletion(IoCompletionHandle, DesiredAccess, ObjectAttributes, Count);
} 	