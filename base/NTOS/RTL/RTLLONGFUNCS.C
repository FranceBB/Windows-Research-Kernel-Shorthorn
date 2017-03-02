/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    Rtllongfuncs.c

Abstract:

    This module contains static data used by RLT routines on Longhorn/Vista.

--*/

#include <ntrtlp.h>

#define RtlLeftChildAvl(x)          (PRTL_BALANCED_LINKS)(RtlLeftChild(x))
#define RtlParentAvl(x)             (PRTL_BALANCED_LINKS)(RtlParent(x))
#define RtlRealPredecessorAvl(x)    (PRTL_BALANCED_LINKS)(RtlRealPredecessor((PRTL_SPLAY_LINKS)(x)))

typedef WORD ATOM;

typedef struct _TABLE_ENTRY_HEADER
{
     RTL_SPLAY_LINKS SplayLinks;
     LIST_ENTRY ListEntry;
     LONGLONG UserData;
} TABLE_ENTRY_HEADER, *PTABLE_ENTRY_HEADER;

FORCEINLINE PRTL_BALANCED_LINKS RtlRightChildAvl 	( 	IN PRTL_BALANCED_LINKS  	Node	) 	
{
    return Node->RightChild;
}

RTL_GENERIC_COMPARE_RESULTS FORCEINLINE RtlpAvlCompareRoutine 	( 	IN PRTL_AVL_TABLE  	Table,
		IN PVOID  	Buffer,
		IN PVOID  	UserData 
	) 		
{
    /* Do the compare */
    return Table->CompareRoutine(Table,
                                 Buffer,
                                 UserData);
}

FORCEINLINE TABLE_SEARCH_RESULT RtlpFindAvlTableNodeOrParent 	( 	IN PRTL_AVL_TABLE  	Table,
		IN PVOID  	Buffer,
		OUT PRTL_BALANCED_LINKS *  	NodeOrParent 
	) 		
{
    PRTL_BALANCED_LINKS CurrentNode, ChildNode;
    RTL_GENERIC_COMPARE_RESULTS Result;

    /* Quick check to see if the table is empty */
    if (!Table->NumberGenericTableElements) return TableEmptyTree;

    /* Set the current node */
    CurrentNode = RtlRightChildAvl(&Table->BalancedRoot);

    /* Start compare loop */
    while (TRUE)
    {
        /* Compare which side is greater */
        Result = RtlpAvlCompareRoutine(Table,
                                       Buffer,
                                       &((PTABLE_ENTRY_HEADER)CurrentNode)->
                                       UserData);
        if (Result == GenericLessThan)
        {
            /* We're less, check if this is the left child */
            ChildNode = RtlLeftChildAvl(CurrentNode);
            if (ChildNode)
            {
                /* Continue searching from this node */
                CurrentNode = ChildNode;
            }
            else
            {
                /* Otherwise, the element isn't in this tree */
                *NodeOrParent = CurrentNode;
                return TableInsertAsLeft;
            }
        }
        else if (Result == GenericGreaterThan)
        {
            /* We're more, check if this is the right child */
            ChildNode = RtlRightChildAvl(CurrentNode);
            if (ChildNode)
            {
                /* Continue searching from this node */
                CurrentNode = ChildNode;
            }
            else
            {
                /* Otherwise, the element isn't in this tree */
                *NodeOrParent = CurrentNode;
                return TableInsertAsRight;
            }
        }
        else
        {
            /* We should've found the node */
            ASSERT(Result == GenericEqual);

            /* Return node found */
            *NodeOrParent = CurrentNode;
            return TableFoundNode;
        }
    }
}

NTSTATUS RtlInvertRangeListEx(PRTL_RANGE_LIST RangeList, PRTL_RANGE_LIST list, UCHAR Attributes, PVOID UserData, PVOID Owner)
{
	return RtlInvertRangeList(RangeList, list);
}

PVOID NTAPI RtlLookupFirstMatchingElementGenericTableAvl( 	IN PRTL_AVL_TABLE  	Table,
		IN PVOID  	Buffer,
		OUT PVOID *  	RestartKey 
	) 		
{
    PRTL_BALANCED_LINKS Node, PreviousNode;
    TABLE_SEARCH_RESULT SearchResult;
    RTL_GENERIC_COMPARE_RESULTS Result = GenericEqual;

    /* Assume failure */
    *RestartKey = NULL;

    /* Find the node */
    SearchResult = RtlpFindAvlTableNodeOrParent(Table, Buffer, &Node);
    if (SearchResult != TableFoundNode) return NULL;

    /* Scan each predecessor until a match is found */
    PreviousNode = Node;
    while (Result == GenericEqual)
    {
        /* Save the node */
        Node = PreviousNode;

        /* Get the predecessor */
        PreviousNode = RtlRealPredecessorAvl(Node);
        if ((!PreviousNode) || (RtlParentAvl(PreviousNode) == PreviousNode)) break;

        /* Check if this node matches */
        Result = RtlpAvlCompareRoutine(Table,
                                       Buffer,
                                       &((PTABLE_ENTRY_HEADER)PreviousNode)->
                                       UserData);
    }

    /* Save the node as the restart key, and return its data */
    *RestartKey = Node;
    return &((PTABLE_ENTRY_HEADER)Node)->UserData;
}

/*unimplemented*/
NTSYSAPI
NTSTATUS
NTAPI
RtlFormatMessage(
    __in PWSTR MessageFormat,
    __in ULONG MaximumWidth,
    __in BOOLEAN IgnoreInserts,
    __in BOOLEAN ArgumentsAreAnsi,
    __in BOOLEAN ArgumentsAreAnArray,
    __in va_list *Arguments,
    __out_bcount_part(Length, *ReturnLength) PWSTR Buffer,
    __in ULONG Length,
    __out_opt PULONG ReturnLength
    )
{
	return 0x00000000;
}
/*
BOOLEAN RtlGetIntegerAtom(ULONG Value, int a2)
{
  ULONG other; // ecx@5
  unsigned __int16 v4; // dx@5
  ULONG variable; // eax@5
  int v6; // ecx@7
  ULONG v7; // ax@15
  const UNICODE_STRING String = {0, 0, L""}; // [sp+0h] [bp-8h]@13

  if ( !(Value & 0xFFFF0000) )
  {
    v7 = Value;
    if ( (unsigned __int16)Value < 0xC000u )
    {
      if ( !(WORD)Value )
        v7 = 0xC000u;
      v6 = a2;
      if ( !a2 )
        return 1;
      goto LABEL_17;
    }
    return 0;
  }
  if ( *(WORD *)Value != 35 )
    return 0;
  other = Value + 2;
  v4 = *(WORD *)(Value + 2);
  variable = Value + 2;
  if ( v4 )
  {
    while ( v4 >= 0x30u && v4 <= 0x39u )
    {
      variable += 2;
      v4 = *(WORD *)variable;
      if ( !*(WORD *)variable )
        goto LABEL_13;
    }
    return 0;
  }
LABEL_13:
  Value = 0;
  String.Length = (USHORT)variable - other;
  String.MaximumLength = variable - other;
  String.Buffer = (PWSTR)other;
  if ( RtlUnicodeStringToInteger(&String, 0xAu, &Value) < 0 )
    return 0;
  v6 = a2;
  if ( a2 )
  {
    v7 = Value;
    if ( Value && Value <= 0xC000 )
    {
LABEL_17:
      *(WORD *)v6 = v7;
      return 1;
    }
    *(WORD *)a2 = 0xC000u;
  }
  return 1;
}*/

BOOLEAN RtlGetIntegerAtom(ULONG IntegerAtom, ATOM AtomName)
{
  ULONG string; // ecx@5
  ULONG other; // dx@5
  ULONG recept; // eax@5
  ULONG unknown; // eax@8
  ATOM v7; // ecx@11
  PUNICODE_STRING receiveString; // [sp+0h] [bp-8h]@16
  PUNICODE_STRING stringReceive; // [sp+2h] [bp-6h]@16
  ULONG obj; // [sp+4h] [bp-4h]@16

  if ( !(AtomName & 0xFFFF0000) )
  {
    unknown = AtomName;
    if ( AtomName < 0xC000u )
    {
      if ( !AtomName )
        unknown = 0xC000u;
      v7 = (ATOM)IntegerAtom;
      if ( !IntegerAtom )
        return 1;
      goto LABEL_12;
    }
    return 0;
  }
  if ( AtomName != 35 )
    return 0;
  string = AtomName + 1;
  other = AtomName;
  recept = AtomName + 1;
  if ( other )
  {
    while ( other >= 0x30u && other <= 0x39u )
    {
      ++recept;
      other = recept;
      if ( !recept )
        goto LABEL_16;
    }
    return 0;
  }
LABEL_16:
  AtomName = 0;
  receiveString = (PUNICODE_STRING)(ULONGLONG)recept;
  stringReceive = (PUNICODE_STRING)(ULONGLONG)string;
  obj = string;
  if ( RtlUnicodeStringToInteger(receiveString, 10, (PULONG)(ULONGLONG)AtomName) < 0 )
    return 0;
  v7 = (ATOM)IntegerAtom;
  if ( !IntegerAtom )
    return 1;
  unknown = AtomName;
  if ( !AtomName || AtomName > 0xC000 )
  {
    IntegerAtom = 0xC000u;
    return 1;
  }
LABEL_12:
  v7 = (unsigned int)unknown;
  return TRUE;
}

NTSTATUS RtlFormatSid_Helper(HANDLE Handle, PSID sid, PVOID TokenInformation)
{
  HANDLE handle; // ebx@1
  NTSTATUS result; // eax@3
  PVOID token; // edi@6
  NTSTATUS status; // esi@6
  ULONG ReturnLength; // [sp+8h] [bp-4h]@6

  handle = Handle;
  if ( !Handle )
  {
    #if !defined(_AMD64_)
    if ( !(*(BYTE *)(ULONGLONG)(__readfsdword(292) + 624) & 8) )
      goto LABEL_5;
	#endif
    result = ZwOpenThreadTokenEx((HANDLE)0xFEu, 8, 1, 512, &Handle);
	goto LABEL_5;
    if ( result < 0 )
    {
      if ( result != 0xC000007C )
        return result;
LABEL_5:
      result = ZwOpenProcessTokenEx((HANDLE)0xFFu, 8, 512, &Handle);
      if ( result < 0 )
        return result;
      goto LABEL_6;
    }
  }
LABEL_6:
  token = TokenInformation;
  status = ZwQueryInformationToken(Handle, TokenUser, TokenInformation, 0x50u, &ReturnLength);
  if ( !handle )
    ZwClose(Handle);
  if ( status >= 0 )
    *(DWORD *)sid = *(DWORD *)token;
  return status;
}

NTSTATUS RtlFormatSidUserKeyPathHelper(HANDLE Handle, PVOID other, PVOID TokenInformation)
{
  HANDLE handle; // ebx@1
  NTSTATUS result; // eax@3
  PVOID token; // edi@6
  NTSTATUS status; // esi@6
  ULONG ReturnLength; // [sp+8h] [bp-4h]@6

  handle = Handle;
  if ( !Handle )
  {
#if defined(_i386_)
    if ( !(*(BYTE *)(__readfsdword(292) + 624) & 8) )
#else
    if ( !(*(BYTE *)(__readgsqword(292) + 624) & 8) )
#endif	
      goto LABEL_5;
    result = ZwOpenThreadTokenEx((HANDLE)-2, 8, 1, 512, &Handle);
    if ( result < 0 )
    {
      if ( result != -1073741700 )
        return result;
LABEL_5:
      result = ZwOpenProcessTokenEx((HANDLE)-1, 8, 512, &Handle);
      if ( result < 0 )
        return result;
      goto LABEL_6;
    }
  }
LABEL_6:
  token = TokenInformation;
  status = ZwQueryInformationToken(Handle, TokenUser, TokenInformation, 0x50u, &ReturnLength);
  if ( !handle )
    ZwClose(Handle);
  if ( status >= 0 )
    other = token;
  return status;
}

//verify //reimplement
NTSTATUS RtlFormatSidUserKeyPathResult(PSID Sid, USHORT a2)
{
  NTSTATUS result; // eax@2
  signed int v3; // [sp-4h] [bp-8h]@5

  if ( RtlValidSid(Sid) == 1 )
  {
    if ( *((BYTE *)Sid + 2) || *((BYTE *)Sid + 3) )
      v3 = 14;
    else
      v3 = 10;
#if defined(_i386_)
    *(DWORD *)a2 = 2 * (v3 + 11 * *((BYTE *)Sid + 1)) + 8;
#else
    a2 = 2 * (v3 + 11 * *((BYTE *)Sid + 1)) + 8;
#endif	
    result = 0;
  }
  else
  {
    result = 0xC0000078u;
  }
  return result;
}

NTSTATUS RtlFormatSidUserKeyPath(PSID Sid, char a2, PUNICODE_STRING Destination)
{
  NTSTATUS result; // eax@2
  PUNICODE_STRING test; // esi@4
  USHORT string; // ax@4
  BOOLEAN verification; // zf@4
  int length; // eax@6
  PWSTR receive; // ecx@8
  NTSTATUS conversion; // edi@8
  BOOLEAN TokenInformation; // [sp+4h] [bp-5Ch]@2
  UNICODE_STRING UnicodeString; // [sp+54h] [bp-Ch]@8
  USHORT repare; // [sp+5Ch] [bp-4h]@3

  if ( Sid || (result = RtlFormatSidUserKeyPathHelper(0, Sid, &TokenInformation), result >= 0) )
  {
    result = RtlFormatSidUserKeyPathResult(Sid, (USHORT)&repare);
    if ( result >= 0 )
    {
      test = Destination;
      string = repare + 34;
      verification = a2 == 0;
      Destination->Length = 0;
      test->MaximumLength = string;
      if ( !verification )
        test->MaximumLength = string + 48;
      length = test->MaximumLength;
#if defined(_i386_)
      test->Buffer = (PWSTR)length;
#else
	  test->Buffer = (PWSTR)(ULONGLONG)length;
#endif	  
      if ( length )
      {
        RtlAppendUnicodeToString(test, L"Registry'\'user");
        receive = test->Buffer;
        UnicodeString.MaximumLength = repare;
        UnicodeString.Buffer = &receive[(unsigned int)test->Length >> 1];
        UnicodeString.Length = 0;
        conversion = RtlConvertSidToUnicodeString(&UnicodeString, Sid, 0);
        if ( conversion < 0 )
          goto LABEL_16;
        test->Length += UnicodeString.Length;
        if ( a2 )
          conversion = RtlAppendUnicodeToString(test, L"Classes'\'Local Settings");
        if ( conversion < 0 )
LABEL_16:
          RtlFreeUnicodeString(test);
        result = conversion;
      }
      else
      {
        result = 0xC0000017u;
      }
    }
  }
  return result;
}

ULONGLONG NTAPI RtlCmDecodeMemIoResource(PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor, PULONGLONG Start)
{
  ULONGLONG result; // qax@1
  ULONG length; // esi@1
  USHORT localFlags; // dx@3

  result = 0;
  length = 0;
  if ( Descriptor->Type == 3 || Descriptor->Type == 1 )
  {
    result = Descriptor->u.Generic.Length;
    length = 0;
  }
  else
  {
    localFlags = Descriptor->Flags;
    if ( localFlags & 0x200 )
    {
      length = Descriptor->u.Generic.Length >> 24;
      result = Descriptor->u.Generic.Length << 8;
    }
    else
    {
      if ( localFlags & 0x400 )
      {
        length = Descriptor->u.Generic.Length >> 16;
        result = Descriptor->u.Generic.Length << 16;
      }
      else
      {
        if ( localFlags & 0x800 )
        {
          length = Descriptor->u.Generic.Length;
          result = 0;
        }
      }
    }
  }
  if ( Start )
    *Start = (ULONGLONG)&Descriptor->u.Generic.Start.HighPart;
  result = length;
  return result;
}

BOOLEAN NTAPI RtlIsNtDdiVersionAvailable(ULONG Version)
{
  BOOLEAN result; // al@3

  if ( Version & 0xFF00 || (BYTE)Version )
    result = 0;
  else
    result = Version <= NTDDI_WS03;
  return result;
}