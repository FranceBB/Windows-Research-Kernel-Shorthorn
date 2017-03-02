/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

   alpclongfuncs.c

Abstract:

    This module contains the routines which implement the
    ALPC Ports for files and registry.

--*/

#include <alpc.h>

ULONG NTAPI AlpcGetHeaderSize(ULONG flags)
{
  ULONG result; 

  result = 8;
  if ( flags & 0x80000000 )
    result = 20;
  if ( flags & 0x40000000 )
    result += 16;
  if ( flags & 0x20000000 )
    result += 20;
  return result;
}

ULONG NTAPI AlpcGetMessageAttribute(PALPC_MESSAGE_ATTRIBUTES attributes, ULONG AttributeFlag)
{
  ULONG result; // eax@3

  if ( !(attributes->AllocatedAttributes & AttributeFlag) || (AttributeFlag - 1) & AttributeFlag )
    result = 0;
  else
#if defined(_i386_)
    result = (ULONG)(attributes + AlpcGetHeaderSize(attributes->AllocatedAttributes & ~(2 * AttributeFlag - 1)));
#else
    result = (ULONG)(ULONGLONG)(attributes + AlpcGetHeaderSize(attributes->AllocatedAttributes & ~(2 * AttributeFlag - 1)));
#endif
  return result;
}

NTSTATUS NTAPI AlpcInitializeMessageAttribute(ULONG flags, PALPC_MESSAGE_ATTRIBUTES Buffer, ULONG BufferSize, PULONG RequiredBufferSize)
{
  ULONG localRequiredBufferSize; // eax@1
  ULONG attribs = 0; // ecx@1
  NTSTATUS result; // eax@2

  localRequiredBufferSize = AlpcGetHeaderSize(flags);
  *RequiredBufferSize = localRequiredBufferSize;
  if ( localRequiredBufferSize <= BufferSize )
  {
    if ( Buffer )
    {
      Buffer->ValidAttributes = 0;
      Buffer->AllocatedAttributes = attribs;
    }
    result = 0;
  }
  else
  {
    result = 0xC0000023u;
  }
  return result;
}


BOOLEAN KdDebuggerEnabled;

POBJECT_TYPE AlpcPortObjectType;

/*subimplemented*/
NTSTATUS NTAPI
NtAlpcAcceptConnectPort(
    __out HANDLE                         PortHandle,
    __in HANDLE                          ConnectionPortHandle,
    __in ULONG                           Flags,
    __in POBJECT_ATTRIBUTES              ObjectAttributes,
    __in PALPC_PORT_ATTRIBUTES           PortAttributes,
    __in_opt PVOID                       PortContext, // opaque value
    __in PPORT_MESSAGE                   ConnectionRequest,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES MessageAttributes,
    __in BOOLEAN                         AcceptConnection
    )
{
	NTSTATUS status;						   
	DbgPrint("A syscall numero 296 NtAlpcAcceptConnectPort foi chamada\n");	
	status = NtAcceptConnectPort(PortHandle, 
							   PortContext, 
							   ConnectionRequest, 
							   AcceptConnection,
							   NULL,
							   NULL);
	DbgPrint("Status: %08x\n",status);
	return status;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcCancelMessage(
		__in HANDLE  	PortHandle,
		__in ULONG  	Flags,
		__in PALPC_CONTEXT_ATTR  	MessageContext 
	) 	
{
	return STATUS_SUCCESS;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcConnectPort( 	
		__out PHANDLE  	PortHandle,
		__in PUNICODE_STRING  	PortName,
		__in POBJECT_ATTRIBUTES  	ObjectAttributes,
		__in_opt PALPC_PORT_ATTRIBUTES  	PortAttributes,
		__in ULONG  	Flags,
		__in_opt PSID  	RequiredServerSid,
		__inout PPORT_MESSAGE  	ConnectionMessage,
		__inout_opt PULONG  	BufferLength,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES  	OutMessageAttributes,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES  	InMessageAttributes,
		__in_opt PLARGE_INTEGER  	Timeout 
	) 	
{
	NTSTATUS status;
	DbgPrint("A syscall numero 298 NtAlpcConnectPort foi chamada\n");	
	status =  NtConnectPort(PortHandle, 
						 PortName, 
						 &PortAttributes->SecurityQos, 
						 NULL, 
						 NULL, 
						 (PULONG)&PortAttributes->MaxMessageLength,
						 NULL,
						 NULL);
	DbgPrint("Status: %08x\n",status);
	return status;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcCreatePort( 	
		__out PHANDLE  	PortHandle,
		__in POBJECT_ATTRIBUTES  	ObjectAttributes,
		__in_opt PALPC_PORT_ATTRIBUTES  	PortAttributes 
	) 		
{
	NTSTATUS status;
	DbgPrint("A syscall numero 299 NtAlpcCreatePort foi chamada\n");	
	status = NtCreatePort(PortHandle, 
						  ObjectAttributes, 
						  sizeof(PortAttributes->MaxViewSize), 
						  sizeof(PortAttributes->MaxMessageLength), 
						  (ULONG)PortAttributes->MaxPoolUsage);	
	DbgPrint("Status: %08x\n",status);
	return status;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcCreatePortSection( 	
		__in HANDLE  	PortHandle,
		__in ULONG  	Flags,
		__in_opt HANDLE  	SectionHandle,
		__in SIZE_T  	SectionSize,
		__out PALPC_HANDLE  	AlpcSectionHandle,
		__out PSIZE_T  	ActualSectionSize 
	) 	
{
	NTSTATUS status;						   
	DbgPrint("A syscall numero 300 NtAlpcCreatePortSection foi chamada\n");
	status = NtCreateSection(&PortHandle, Flags, NULL, NULL, 1, 1, AlpcSectionHandle);
	DbgPrint("Status: %08x\n",status);	
	return status;
}

NTSTATUS NTAPI NtAlpcCreateResourceReserve(
		__in HANDLE PortHandle, 
		__reserved ULONG Flags, 
		__in SIZE_T MessageSize, 
		__out PALPC_HANDLE ResourceId)
{
	DbgPrint("A syscall numero 301 NtAlpcCreateResourceReserve foi chamada\n");	
	return STATUS_SUCCESS;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcCreateSectionView( 	
		__in HANDLE  	PortHandle,
		__reserved ULONG  	Flags,
		__inout PALPC_DATA_VIEW_ATTR  	ViewAttributes 
	) 	
{
	NTSTATUS status;						   
	DbgPrint("A syscall numero 302 NtAlpcCreateSectionView foi chamada\n");
	status = NtMapViewOfSection(ViewAttributes->SectionHandle, 
								PortHandle, 
								ViewAttributes->ViewBase, 
								0, 
								0, 
								0, 
								(PSIZE_T)ViewAttributes->ViewSize, 
								0, 
								0, 
								0);
	DbgPrint("Status: %08x\n",status);	
	return status;	
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcCreateSecurityContext( 	
		__in HANDLE  	PortHandle,
		__reserved ULONG  	Flags,
		__inout PALPC_SECURITY_ATTR  	SecurityAttribute 
	) 	
{
	return STATUS_SUCCESS;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcDeletePortSection( 	
		__in HANDLE  	PortHandle,
		__reserved ULONG  	Flags,
		__in ALPC_HANDLE  	SectionHandle 
	) 	
{
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtAlpcDeleteResourceReserve(	
		__in HANDLE 	PortHandle,
		__reserved ULONG 	Flags,
		__in ALPC_HANDLE 	ResourceId 
)
{
	return STATUS_SUCCESS;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcDeleteSectionView( 	
		__in HANDLE  	PortHandle,
		__reserved ULONG  	Flags,
		__in PVOID  	ViewBase 
	) 	
{
	DbgPrint("A syscall numero 306 NtAlpcDeleteSectionView foi chamada\n");	
	return STATUS_SUCCESS;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcDeleteSecurityContext( 	
		__in HANDLE  	PortHandle,
		__reserved ULONG  	Flags,
		__in ALPC_HANDLE  	ContextHandle 
	) 	
{
	ContextHandle = NULL;
	DbgPrint("A syscall numero 307 NtAlpcDeleteSecurityContext foi chamada\n");	
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtAlpcDisconnectPort(
		__in HANDLE PortHandle, 
		__in ULONG Flags)
{
	DbgPrint("A syscall numero 308 NtAlpcDisconnectPort foi chamada\n");	
	PortHandle = NULL;
	return STATUS_SUCCESS;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcImpersonateClientOfPort( 	
		__in HANDLE  	PortHandle,
		__in PPORT_MESSAGE  	PortMessage,
		__reserved PVOID  	Reserved 
	) 	
{
	NTSTATUS status;						   
	DbgPrint("A syscall numero 309 NtAlpcImpersonateClientOfPort foi chamada\n");
	status = NtImpersonateClientOfPort(PortHandle, PortMessage);
	DbgPrint("Status: %08x\n",status);	
	return status;	
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcQueryInformation( 	
		__in HANDLE  	PortHandle,
		__in ALPC_PORT_INFORMATION_CLASS  	PortInformationClass,
		__out_bcount(Length) PVOID  	PortInformation,
		__in ULONG  	Length,
		__out_opt PULONG  	ReturnLength 
	) 	
{
	NTSTATUS status;						   
	DbgPrint("A syscall numero 310 NtAlpcQueryInformation foi chamada\n");	
	status = NtQueryInformationPort(PortHandle, 
								  PortInformationClass, 
								  PortInformation, 
								  Length, 
								  ReturnLength);
	DbgPrint("Status: %08x\n",status);	
	return status;	
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcSendWaitReceivePort( 	
		__in HANDLE  	PortHandle,
		__in ULONG  	Flags,
		__in_opt PPORT_MESSAGE  	SendMessage,
		__in_opt PALPC_MESSAGE_ATTRIBUTES  	SendMessageAttributes,
		__inout_opt PPORT_MESSAGE  	ReceiveMessage,
		__inout_opt PULONG  	BufferLength,
		__inout_opt PALPC_MESSAGE_ATTRIBUTES  	ReceiveMessageAttributes,
		__in_opt PLARGE_INTEGER  	Timeout 
	) 	
{
	NTSTATUS status;
	DbgPrint("A syscall numero 311 NtAlpcSendWaitReceivePort foi chamada\n");	
	status = NtReplyWaitReceivePort(PortHandle, NULL, SendMessage, ReceiveMessage);//NtReplyWaitReceivePortEx(PortHandle, NULL, SendMessage, ReceiveMessage, Timeout);
	DbgPrint("Status: %08x\n", status);	
	return status;
}

/*subimplemented*/
NTSTATUS NTAPI NtAlpcSetInformation( 	
		__in HANDLE  	PortHandle,
		__in ALPC_PORT_INFORMATION_CLASS  	PortInformationClass,
		__in_bcount(Length) PVOID  	PortInformation,
		__in ULONG  	Length 
	) 	
{
	NTSTATUS status;
	DbgPrint("A syscall numero 312 NtAlpcSetInformation foi chamada\n");	
	//status = NtSetInformationObject(PortHandle, PortInformationClass, PortInformation, Length);
	//status = NtSetInformationThread(PortHandle, ThreadImpersonationToken, PortInformation, sizeof(HANDLE));
	//DbgPrint("Status: %08x\n", status);	
	return STATUS_SUCCESS;
}