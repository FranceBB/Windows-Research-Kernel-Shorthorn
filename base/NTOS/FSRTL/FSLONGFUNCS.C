/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    FSRTLLONGHORNFUNCTIONS.c

Abstract:

    This module provides three routines that allow filesystem filter drivers
    to associate state with FILE_OBJECTs -- for filesystems which support
    an extended FSRTL_COMMON_HEADER with FsContext.

    These routines depend on fields (FastMutext and FilterContexts)
    added at the end of FSRTL_COMMON_HEADER in NT 5.0.

    Filesystems should set FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS if
    these new fields are supported.  They must also initialize the mutex
    and list head.

    Filter drivers must use a common header for the context they wish to
    associate with a file object:

        FSRTL_FILTER_CONTEXT:
                LIST_ENTRY  Links;
                PVOID       OwnerId;
                PVOID       InstanceId;

    The OwnerId is a bit pattern unique to each filter driver
    (e.g. the device object).

    The InstanceId is used to specify a particular instance of the context
    data owned by a filter driver (e.g. the file object).

--*/

#include "FsRtlP.h"

PPAGED_LOOKASIDE_LIST page = NULL;
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
PKSEMAPHORE semaphore;
int count = 0;
PCWSTR used = L"'\'";

NTSTATUS
NTAPI FsRtlAddBaseMcbEntryEx(IN PBASE_MCB Mcb, IN LONGLONG Vbn, IN LONGLONG Lbn, IN LONGLONG SectorCount)
{
	return FsRtlAddBaseMcbEntry(Mcb, Vbn, Lbn, SectorCount); 
}

BOOLEAN FsRtlInitializeBaseMcbEx(PBASE_MCB Mcb, POOL_TYPE PoolType, USHORT Flags)
{
  FsRtlInitializeBaseMcb(Mcb,PoolType);
  return TRUE;
}

NTKERNELAPI
NTSTATUS
NTAPI
FsRtlNotifyVolumeEventEx(
   IN PFILE_OBJECT FileObject,
   IN ULONG EventCode,
   IN PTARGET_DEVICE_CUSTOM_NOTIFICATION Event)
{
	return FsRtlNotifyVolumeEvent(FileObject, EventCode);
}

NTSTATUS FsRtlFindCreateElement(PFILE_OBJECT object, char a2, int a3, int a4, int a5, int a6)
{
  char *v6; // ebx@3
  PVPB v7; // edx@3
  char v8; // zf@3
  NTSTATUS status; // [sp+8h] [bp+8h]@3

  if ( a6 )
#if defined(_i386_)
      *(DWORD *)a6 = 0;
#else
     *(DWORD *)(ULONGLONG)a6 = 0;
#endif
  v6 = (char *)&object->Vpb;
  v7 = object->Vpb;
  v8 = (PVPB *)v7 == &object->Vpb;
  status = 0xC0000225u;
  if ( !v8 )
  {
    while ( memcmp(&v7->DeviceObject, &a2, 16) )
    {
      v7 = *(PVPB *)&v7->Type;
      if ( (char *)v7 == v6 )
        return status;
    }
    status = 0;
    if ( a6 )
      a6 = a5;
  }
  return status;
}

/*unimplemented*/
VOID FsRtlTeardownPerFileContexts(
  IN  PVOID *PerFileContextPointer
)
{
	;
}

NTSTATUS FsRtlValidateReparsePointBuffer(ULONG BufferLength, PREPARSE_DATA_BUFFER ReparseBuffer)
{
  PVOID *v3; // ecx@4
  DWORD v4; // edi@4
  WORD v5; // dx@27
  int v6; // ecx@29
  WORD v7; // cx@33
  WORD v8; // bx@34
  signed int v9; // esi@34
  signed int v10; // edx@34
  int v11; // ecx@34
  signed __int16 v12; // di@35
  signed int status; // [sp+10h] [bp+Ch]@35

  if ( BufferLength < 8 || BufferLength > 0x4000 )
    return -1073741192;
  v3 = (PVOID *)ReparseBuffer->ReparseDataLength;
  v4 = ReparseBuffer->ReparseTag;
#if defined(_i386_)
  if ( v3 + 2 != (PVOID *)BufferLength && v3 + 6 != (PVOID *)BufferLength
    || v3 + 2 == (PVOID *)BufferLength && !(v4 & 0x80000000)
    || v3 + 6 == (PVOID *)BufferLength
    && (!(v4 & 0x80000000)
     && !*(DWORD *)&ReparseBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameOffset
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameLength
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[0]
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[0]
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[1]
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[1]
     || v4 == 0xA0000003
     || v4 == 0xA000000C) )
#else
  if ( v3 + 2 != (PVOID *)(ULONGLONG)BufferLength && v3 + 6 != (PVOID *)(ULONGLONG)BufferLength
    || v3 + 2 == (PVOID *)(ULONGLONG)BufferLength && ! (v4 & 0x80000000)
    || v3 + 6 == (PVOID *)(ULONGLONG)BufferLength
    && (!(v4 & 0x80000000)
     && !*(DWORD *)&ReparseBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameOffset
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameLength
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.Flags
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[0]
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[0]
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[1]
     && !ReparseBuffer->SymbolicLinkReparseBuffer.PathBuffer[1]
     || v4 == 0xA0000003
     || v4 == 0xA000000C) )
#endif  
    return 0xC0000278u;
  if ( !(v4 & 0xFFF0000) && v4 && v4 != 1 )
  {
    if ( v4 == 0xA0000003 )
    {
      v5 = ReparseBuffer->ReparseDataLength;
      if ( v5 >= 8u )
      {
        if ( !ReparseBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset )
        {
          v6 = ReparseBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength;
          if ( ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameOffset == v6 + 2 )
          {
            if ( v5 == ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameLength + v6 + 12 )
              return 0;
          }
        }
      }
    }
    else
    {
      if ( v4 != 0xA000000C
        || (v7 = ReparseBuffer->ReparseDataLength, v7 >= 0xCu)
        && (v8 = ReparseBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength,
            v9 = ReparseBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset,
            v10 = ReparseBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength,
            v11 = v7 + 8,
            v11 >= v9 + v10 + 20)
        && (v12 = ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameLength,
            status = ReparseBuffer->SymbolicLinkReparseBuffer.PrintNameOffset,
            v11 >= (unsigned __int16)v12 + status + 20)
        && v8
        && v12
        && v10 % 2 != 1
        && (unsigned __int16)v12 % 2 != 1
        && v9 % 2 != 1
        && status % 2 != 1 )
        return 0;
    }
    return 0xC0000278u;
  }
  return 0xC0000276u;
}

/* unimplemented*/
NTSTATUS FsRtlFindExtraCreateParameter(PVOID *a1, LPCGUID a2, PVOID *a3)
{
  return 0x0000000;
}

NTSTATUS FsRtlCancellableWaitForIoCompletion(PIRP Irp, PVOID Object, PLARGE_INTEGER Timeout)
{
  NTSTATUS verify; // eax@6
  BOOLEAN WaitMode; // [sp+Ch] [bp-14h]@2
  NTSTATUS status; // [sp+10h] [bp-10h]@6
  BOOLEAN verification; // [sp+14h] [bp-Ch]@4
  LARGE_INTEGER Interval; // [sp+18h] [bp-8h]@10

#if defined(_i386_)
  if ( IoIsSystemThread((PETHREAD)__readfsdword(292)) )
#else
  if ( IoIsSystemThread((PETHREAD)__readgsqword(292)) )
#endif
    WaitMode = Irp->RequestorMode;
  else
    WaitMode = 1;
  verification = 1;
  if ( WaitMode == 1 )
    verification = KeSetKernelStackSwapEnable(0);
  verify = KeWaitForMutexObject(Object, 0, WaitMode, 0, Timeout);
  status = verify;
  if ( verify == 192 || verify == 258 )
  {
    if ( !*((DWORD *)Object + 1) )
    {
      if ( IoCancelIrp(Irp) )
      {
        Interval.QuadPart = -100000i64;
        while ( !*((DWORD *)Object + 1) )
          KeDelayExecutionThread(0, 0, &Interval);
      }
      else
      {
        KeWaitForMutexObject(Object, 0, 0, 0, 0);
      }
    }
    if ( status == 192 )
      status = 0xC0000120u;
  }
  if ( WaitMode == 1 )
    KeSetKernelStackSwapEnable(verification);
  return status;
}

NTSTATUS FsRtlCancellableWaitForCompletion(PIRP Irp, PVOID Semaphore, PLARGE_INTEGER Timeout)
{
  NTSTATUS status; // eax@6
  LARGE_INTEGER Interval; // [sp+0h] [bp-10h]@10
  BOOLEAN verification; // [sp+8h] [bp-8h]@4
  KPROCESSOR_MODE WaitMode[4]; // [sp+Ch] [bp-4h]@2
  NTSTATUS Timeouta; // [sp+20h] [bp+10h]@6

#if defined(_i386_)
  if ( PsIsSystemThread((PETHREAD)__readfsdword(292)) )
#else
  if ( PsIsSystemThread((PETHREAD)__readgsqword(292)) )
#endif
    WaitMode[0] = Irp->RequestorMode;
  else
    WaitMode[0] = 1;
  verification = 1;
  if ( WaitMode[0] == 1 )
    verification = KeSetKernelStackSwapEnable(0);
  status = KeWaitForSingleObject(Semaphore, 0, WaitMode[0], 0, Timeout);
  Timeouta = status;
  if ( status == 192 || status == 258 )
  {
    if ( !KeReadStateEvent((PRKEVENT)Semaphore) )
    {
      if ( IoCancelIrp(Irp) )
      {
        Interval.QuadPart = -100000i64;
        while ( !KeReadStateEvent((PRKEVENT)Semaphore) )
          KeDelayExecutionThread(0, 0, &Interval);
      }
      else
      {
        KeWaitForSingleObject(Semaphore, 0, 0, 0, 0);
      }
    }
    if ( Timeouta == 192 )
      Timeouta = 0xC0000120u;
  }
  if ( WaitMode[0] == 1 )
    KeSetKernelStackSwapEnable(verification);
  return Timeouta;
}

NTSTATUS FsRtlRegisterUncProviderExStringHelper(PHANDLE FileHandle, PCWSTR SourceString)
{
  NTSTATUS result; // eax@1
  OBJECT_ATTRIBUTES ObjectAttributes; // [sp+8h] [bp-28h]@1
  struct _IO_STATUS_BLOCK IoStatusBlock; // [sp+20h] [bp-10h]@1
  UNICODE_STRING DestinationString; // [sp+28h] [bp-8h]@1

  RtlInitUnicodeString(&DestinationString, SourceString);
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.Length = 24;
  ObjectAttributes.RootDirectory = 0;
  ObjectAttributes.Attributes = 0;
  ObjectAttributes.SecurityDescriptor = 0;
  ObjectAttributes.SecurityQualityOfService = 0;
  result = ZwCreateFile(FileHandle, 0x40000000u, &ObjectAttributes, &IoStatusBlock, 0, 0x80u, 3u, 1u, 0, 0, 0);
  if ( result < 0 || (result = IoStatusBlock.Status, IoStatusBlock.Status < 0) )
    *FileHandle = (HANDLE)-1;
  return result;
}

NTSTATUS FsRtlRegisterUncProviderExStatusHelper(HANDLE Handle, ULONG InputBufferLength, PUNICODE_STRING RedirDevName, PDEVICE_OBJECT DeviceObject)
{
  PULONG resp; // esi@1
  PVOID *buffer; // eax@2
  PVOID other; // ebx@2
  NTSTATUS status; // edi@3
  NTSTATUS result; // eax@4
  struct _IO_STATUS_BLOCK IoStatusBlock; // [sp+4h] [bp-8h]@3
  SIZE_T InputBufferLengtha; // [sp+18h] [bp+Ch]@2

#if defined(_i386_)
  resp = (PULONG)InputBufferLength;
#else
  resp = (PULONG)(ULONGLONG)InputBufferLength;
#endif
  if ( InputBufferLength )
  {
    InputBufferLengtha = InputBufferLength + 20;
    buffer = (PVOID *)ExAllocatePoolWithTag(0, InputBufferLengtha, 0x6E755346u);
    other = buffer;
    if ( buffer )
    {
      buffer[1] = buffer + 4;
      buffer = (PVOID *)resp;
      *((WORD *)buffer + 1) = *(WORD *)resp;
      buffer[2] = RedirDevName;
      buffer[3] = DeviceObject;
#if defined(_i386_)
      memcpy(buffer + 4, (const void *)resp[1], (SIZE_T)resp);
      status = NtFsControlFile(Handle, 0, 0, 0, &IoStatusBlock, 0x100004u, buffer, InputBufferLengtha, 0, 0);	 
#else
      memcpy(buffer + 4, (const void *)(ULONGLONG)resp[1], (SIZE_T)(ULONGLONG)resp);
      status = NtFsControlFile(Handle, 0, 0, 0, &IoStatusBlock, 0x100004u, buffer, (ULONG)(ULONGLONG)InputBufferLengtha, 0, 0);	  
#endif
      if ( status == 259 )
      {
        NtWaitForSingleObject(Handle, 1u, 0);
        status = IoStatusBlock.Status;
      }
      ExFreePoolWithTag(other, 0);
      result = status;
    }
    else
    {
      result = 0xC000009Au;
    }
  }
  else
  {
    result = 0xC000000Du;
  }
  return result;
}

//review
NTSTATUS FsRtlRegisterUncProviderEx(PHANDLE MupHandle, ULONG InputBufferLength, PUNICODE_STRING string, PDEVICE_OBJECT DeviceObject)
{
  /*NTSTATUS status; // ebx@1
  HANDLE Handle; // [sp+Ch] [bp-4h]@1

  Handle = (HANDLE)-1;
  
  KeInitializeSemaphore(semaphore, 0,100);
  KeWaitForSingleObject(semaphore, 0, 0, 0, 0);
  status = FsRtlRegisterUncProviderExStringHelper(&Handle, used);
  if ( status < 0 || (status = FsRtlRegisterUncProviderExStatusHelper(Handle, InputBufferLength, string, DeviceObject), status < 0) )
  {
    if ( Handle != (HANDLE)-1 && Handle )
      ZwClose(Handle);
    *MupHandle = (HANDLE)-1;
  }
  else
  {
    ++count;
    *MupHandle = Handle;
  }
  KeReleaseSemaphore(semaphore, 0, 1, 0);
  return status;*/
  return 0x00000000;
}