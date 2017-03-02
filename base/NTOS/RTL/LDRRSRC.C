/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    ldrrsrc.c

Abstract: 

    Loader API calls for accessing resource sections.

--*/

#include "ntrtlp.h"

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE,LdrAccessResource)
#pragma alloc_text(PAGE,LdrpAccessResourceData)
#pragma alloc_text(PAGE,LdrpAccessResourceDataNoMultipleLanguage)
#pragma alloc_text(PAGE,LdrLoadAlternateResourceModule)
#pragma alloc_text(PAGE,LdrFindEntryForAddress)
#pragma alloc_text(PAGE,LdrFindResource_U)
#pragma alloc_text(PAGE,LdrFindResourceEx_U)
#pragma alloc_text(PAGE,LdrFindResourceDirectory_U)
#pragma alloc_text(PAGE,LdrpCompareResourceNames_U)
#pragma alloc_text(PAGE,LdrpSearchResourceSection_U)
#pragma alloc_text(PAGE,LdrEnumResources)
#endif

#define USE_RC_CHECKSUM

// winuser.h
#define IS_INTRESOURCE(_r) (((ULONG_PTR)(_r) >> 16) == 0)
#define RT_VERSION                         16
#define RT_MANIFEST                        24
#define CREATEPROCESS_MANIFEST_RESOURCE_ID  1
#define ISOLATIONAWARE_MANIFEST_RESOURCE_ID 2
#define MINIMUM_RESERVED_MANIFEST_RESOURCE_ID 1
#define MAXIMUM_RESERVED_MANIFEST_RESOURCE_ID 16

#define LDRP_MIN(x,y) (((x)<(y)) ? (x) : (y))

#define DPFLTR_LEVEL_STATUS(x) ((NT_SUCCESS(x) \
                                    || (x) == STATUS_OBJECT_NAME_NOT_FOUND    \
                                    || (x) == STATUS_RESOURCE_DATA_NOT_FOUND  \
                                    || (x) == STATUS_RESOURCE_TYPE_NOT_FOUND  \
                                    || (x) == STATUS_RESOURCE_NAME_NOT_FOUND  \
                                    ) \
                                ? DPFLTR_TRACE_LEVEL : DPFLTR_WARNING_LEVEL)
//This is add for Full mui Support			

#define NO_ALTERNATE_RESOURCE_MODULE    (PVOID)(-1)		

#define  MEMBLOCKSIZE 32

#define  RESMODSIZE sizeof(ALT_RESOURCE_MODULE)
					
//
// Alternate Resources Support
//
typedef struct _ALT_RESOURCE_MODULE
{
    LANGID LangId;
    PVOID ModuleBase;
    PVOID AlternateModule;
} ALT_RESOURCE_MODULE, *PALT_RESOURCE_MODULE;
					
ERESOURCE PsLoadedModuleResource;					
					
LANGID UILangId, InstallLangId, DefaultLangId, ImpersonateLangId;

ULONG AlternateResourceModuleCount;

ULONG AltResMemBlockCount;

PALT_RESOURCE_MODULE AlternateResourceModules;						

NTSTATUS
LdrAccessResource(
    IN PVOID DllHandle,
    IN const IMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry,
    OUT PVOID *Address OPTIONAL,
    OUT PULONG Size OPTIONAL
    )

/*++

Routine Description:

    This function locates the address of the specified resource in the
    specified DLL and returns its address.

Arguments:

    DllHandle - Supplies a handle to the image file that the resource is
        contained in.

    ResourceDataEntry - Supplies a pointer to the resource data entry in
        the resource data section of the image file specified by the
        DllHandle parameter.  This pointer should have been one returned
        by the LdrFindResource function.

    Address - Optional pointer to a variable that will receive the
        address of the resource specified by the first two parameters.

    Size - Optional pointer to a variable that will receive the size of
        the resource specified by the first two parameters.

--*/

{

    NTSTATUS Status;
    RTL_PAGED_CODE();

    Status =
        LdrpAccessResourceData(
          DllHandle,
          ResourceDataEntry,
          Address,
          Size
          );

#if DBG
    if (!NT_SUCCESS(Status)) {
        KdPrintEx((DPFLTR_LDR_ID, DPFLTR_LEVEL_STATUS(Status), "LDR: %s() exiting 0x%08lx\n", __FUNCTION__, Status));
    }
#endif
    return Status;
}

NTSTATUS
LdrpAccessResourceDataNoMultipleLanguage(
    IN PVOID DllHandle,
    IN const IMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry,
    OUT PVOID *Address OPTIONAL,
    OUT PULONG Size OPTIONAL
    )

/*++

Routine Description:

    This function returns the data necessary to actually examine the
    contents of a particular resource, without allowing for the .mui
    feature. It used to be the tail of LdrpAccessResourceData, from
    which it is now called.

Arguments:

    DllHandle - Supplies a handle to the image file that the resource is
        contained in.

    ResourceDataEntry - Supplies a pointer to the resource data entry in
        the resource data directory of the image file specified by the
        DllHandle parameter.  This pointer should have been one returned
        by the LdrFindResource function.

    Address - Optional pointer to a variable that will receive the
        address of the resource specified by the first two parameters.

    Size - Optional pointer to a variable that will receive the size of
        the resource specified by the first two parameters.

--*/

{
    PIMAGE_RESOURCE_DIRECTORY ResourceDirectory;
    ULONG ResourceSize;
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG_PTR VirtualAddressOffset;
    PIMAGE_SECTION_HEADER NtSection;
    NTSTATUS Status = STATUS_SUCCESS;

    RTL_PAGED_CODE();

    try {
        ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
            RtlImageDirectoryEntryToData(DllHandle,
                                         TRUE,
                                         IMAGE_DIRECTORY_ENTRY_RESOURCE,
                                         &ResourceSize
                                         );
        if (!ResourceDirectory) {
            return STATUS_RESOURCE_DATA_NOT_FOUND;
        }

        if (LDR_IS_DATAFILE(DllHandle)) {
            ULONG ResourceRVA;
            DllHandle = LDR_DATAFILE_TO_VIEW(DllHandle);
            NtHeaders = RtlImageNtHeader( DllHandle );
            if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                ResourceRVA=((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].VirtualAddress;
            } else if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                ResourceRVA=((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].VirtualAddress;
            } else {
                ResourceRVA = 0;
            }

            if (!ResourceRVA) {
                return STATUS_RESOURCE_DATA_NOT_FOUND;
                }

            VirtualAddressOffset = (ULONG_PTR)DllHandle + ResourceRVA - (ULONG_PTR)ResourceDirectory;

            //
            // Now, we must check to see if the resource is not in the
            // same section as the resource table.  If it's in .rsrc1,
            // we've got to adjust the RVA in the ResourceDataEntry
            // to point to the correct place in the non-VA data file.
            //
            NtSection = RtlSectionTableFromVirtualAddress( NtHeaders, DllHandle, ResourceRVA);

            if (!NtSection) {
                return STATUS_RESOURCE_DATA_NOT_FOUND;
            }

            if ( ResourceDataEntry->OffsetToData > NtSection->Misc.VirtualSize ) {
                ULONG rva;

                rva = NtSection->VirtualAddress;
                NtSection = RtlSectionTableFromVirtualAddress(NtHeaders,
                                                             DllHandle,
                                                             ResourceDataEntry->OffsetToData
                                                             );
                if (!NtSection) {
                    return STATUS_RESOURCE_DATA_NOT_FOUND;
                }
                VirtualAddressOffset +=
                        ((ULONG_PTR)NtSection->VirtualAddress - rva) -
                        ((ULONG_PTR)RtlAddressInSectionTable ( NtHeaders, DllHandle, NtSection->VirtualAddress ) - (ULONG_PTR)ResourceDirectory);
            }
        } else {
            VirtualAddressOffset = 0;
        }

        if (ARGUMENT_PRESENT( Address )) {
            *Address = (PVOID)( (PCHAR)DllHandle +
                                (ResourceDataEntry->OffsetToData - VirtualAddressOffset)
                              );
        }

        if (ARGUMENT_PRESENT( Size )) {
            *Size = ResourceDataEntry->Size;
        }

    }    except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

#if DBG
    if (!NT_SUCCESS(Status)) {
        KdPrintEx((DPFLTR_LDR_ID, DPFLTR_LEVEL_STATUS(Status), "LDR: %s() exiting 0x%08lx\n", __FUNCTION__, Status));
    }
#endif
    return Status;
}


NTSTATUS
LdrpAccessResourceData(
    IN PVOID DllHandle,
    IN const IMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry,
    OUT PVOID *Address OPTIONAL,
    OUT PULONG Size OPTIONAL
    )

/*++

Routine Description:

    This function returns the data necessary to actually examine the
    contents of a particular resource.

Arguments:

    DllHandle - Supplies a handle to the image file that the resource is
        contained in.

    ResourceDataEntry - Supplies a pointer to the resource data entry in
   the resource data directory of the image file specified by the
        DllHandle parameter.  This pointer should have been one returned
        by the LdrFindResource function.

    Address - Optional pointer to a variable that will receive the
        address of the resource specified by the first two parameters.

    Size - Optional pointer to a variable that will receive the size of
        the resource specified by the first two parameters.

--*/

{
    PIMAGE_RESOURCE_DIRECTORY ResourceDirectory;
    ULONG ResourceSize;
    PIMAGE_NT_HEADERS NtHeaders;
    NTSTATUS Status = STATUS_SUCCESS;

    RTL_PAGED_CODE();

    Status =
        LdrpAccessResourceDataNoMultipleLanguage(
            DllHandle,
            ResourceDataEntry,
            Address,
            Size
            );

    if (!NT_SUCCESS(Status)) {
        KdPrintEx((DPFLTR_LDR_ID, DPFLTR_LEVEL_STATUS(Status), "LDR: %s() exiting 0x%08lx\n", __FUNCTION__, Status));
    }
    return Status;
}


NTSTATUS
LdrFindEntryForAddress(
    IN PVOID Address,
    OUT PLDR_DATA_TABLE_ENTRY *TableEntry
    )
/*++

Routine Description:

    This function returns the load data table entry that describes the virtual
    address range that contains the passed virtual address.

Arguments:

    Address - Supplies a 32-bit virtual address.

    TableEntry - Supplies a pointer to the variable that will receive the
        address of the loader data table entry.


Return Value:

    Status

--*/
{
    PPEB_LDR_DATA Ldr;
    PLIST_ENTRY Head, Next;
    PLDR_DATA_TABLE_ENTRY Entry;
    PIMAGE_NT_HEADERS NtHeaders;
    PVOID ImageBase;
    PVOID EndOfImage;
    NTSTATUS Status;

    Ldr = NtCurrentPeb()->Ldr;
    if (Ldr == NULL) {
        Status = STATUS_NO_MORE_ENTRIES;
        goto Exit;
        }

    Entry = (PLDR_DATA_TABLE_ENTRY) Ldr->EntryInProgress;
    if (Entry != NULL) {
        NtHeaders = RtlImageNtHeader( Entry->DllBase );
        if (NtHeaders != NULL) {
            ImageBase = (PVOID)Entry->DllBase;

            EndOfImage = (PVOID)
                ((ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage);

            if ((ULONG_PTR)Address >= (ULONG_PTR)ImageBase && (ULONG_PTR)Address < (ULONG_PTR)EndOfImage) {
                *TableEntry = Entry;
                Status = STATUS_SUCCESS;
                goto Exit;
                }
            }
        }

    Head = &Ldr->InMemoryOrderModuleList;
    Next = Head->Flink;
    while ( Next != Head ) {
        Entry = CONTAINING_RECORD( Next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

        NtHeaders = RtlImageNtHeader( Entry->DllBase );
        if (NtHeaders != NULL) {
            ImageBase = (PVOID)Entry->DllBase;

            EndOfImage = (PVOID)
                ((ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage);

            if ((ULONG_PTR)Address >= (ULONG_PTR)ImageBase && (ULONG_PTR)Address < (ULONG_PTR)EndOfImage) {
                *TableEntry = Entry;
                Status = STATUS_SUCCESS;
                goto Exit;
                }
            }

        Next = Next->Flink;
        }

    Status = STATUS_NO_MORE_ENTRIES;
Exit:
    if (!NT_SUCCESS(Status)) {
        KdPrintEx((DPFLTR_LDR_ID, DPFLTR_LEVEL_STATUS(Status), "LDR: %s() exiting 0x%08lx\n", __FUNCTION__, Status));
    }
    return( Status );
}

/*
NTSTATUS
LdrFindResource_U(
    IN PVOID DllHandle,
    IN const ULONG_PTR* ResourceIdPath,
    IN ULONG ResourceIdPathLength,
    OUT PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry
    )

/*++

Routine Description:

    This function locates the address of the specified resource in the
    specified DLL and returns its address.

Arguments:

    DllHandle - Supplies a handle to the image file that the resource is
        contained in.

    ResourceIdPath - Supplies a pointer to an array of 32-bit resource
        identifiers.  Each identifier is either an integer or a pointer
        to a STRING structure that specifies a resource name.  The array
        is used to traverse the directory structure contained in the
        resource section in the image file specified by the DllHandle
        parameter.

    ResourceIdPathLength - Supplies the number of elements in the
        ResourceIdPath array.

    ResourceDataEntry - Supplies a pointer to a variable that will
        receive the address of the resource data entry in the resource
        data section of the image file specified by the DllHandle
        parameter.
--

{
    RTL_PAGED_CODE();

    return LdrpSearchResourceSection_U(
      DllHandle,
      ResourceIdPath,
      ResourceIdPathLength,
      0,                // Look for a leaf node, ineaxt lang match
      (PVOID *)ResourceDataEntry
      );
}*/

int 
push_language( 	
	USHORT *  	list,
	ULONG  	pos,
	WORD  	lang 
) 		
{
    ULONG i;
    for (i = 0; i < pos; i++) 
		if (list[i] == lang) 
			return pos;
    list[pos++] = lang;
    return pos;
}

PIMAGE_RESOURCE_DIRECTORY 
LdrpSearchResourceSection_U_by_id( 	
	PIMAGE_RESOURCE_DIRECTORY  	dir,
	WORD  	id,
	PVOID  	root,
	int  	want_dir 
) 		
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    int min, max, pos;

    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    min = dir->NumberOfNamedEntries;
    max = min + dir->NumberOfIdEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        if (entry[pos].Id == id)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                DbgPrint("root %p dir %p id %04x ret %p\n",
                       root, dir, id, (const char*)root + entry[pos].OffsetToDirectory);
                return (IMAGE_RESOURCE_DIRECTORY *)((char *)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (entry[pos].Id > id) max = pos - 1;
        else min = pos + 1;
    }
    DbgPrint("root %p dir %p id %04x not found\n", root, dir, id );
    return NULL;
}

PIMAGE_RESOURCE_DIRECTORY 
LdrpSearchResourceSection_U_by_name( 	
	PIMAGE_RESOURCE_DIRECTORY  	dir,
	LPCWSTR  	name,
	PVOID  	root,
	int  want_dir 
) 		
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    const IMAGE_RESOURCE_DIR_STRING_U *str;
    int min, max, res, pos;
    size_t namelen;

    if (!((ULONG_PTR)name & 0xFFFF0000)) 
		return LdrpSearchResourceSection_U_by_id( dir, (WORD)name & 0xFFFF, root, want_dir );
    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    namelen = wcslen(name);
    min = 0;
    max = dir->NumberOfNamedEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const char *)root + entry[pos].NameOffset);
        res = _wcsnicmp( name, str->NameString, str->Length );
        if (!res && namelen == str->Length)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                DbgPrint("root %p dir %p name %ws ret %p\n",
                       root, dir, name, (const char*)root + entry[pos].OffsetToDirectory);
                return (IMAGE_RESOURCE_DIRECTORY *)((PCHAR)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    DbgPrint("root %p dir %p name %ws not found\n", root, dir, name);
    return NULL;
}

PIMAGE_RESOURCE_DIRECTORY 
find_first_entry( 	
	PIMAGE_RESOURCE_DIRECTORY  	dir,
	PVOID root,
	int want_dir 
) 		
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    int pos;

    for (pos = 0; pos < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; pos++)
    {
        if (!entry[pos].DataIsDirectory == !want_dir)
            return (IMAGE_RESOURCE_DIRECTORY *)((PCHAR)root + entry[pos].OffsetToDirectory);
    }
    return NULL;
}

NTSTATUS 
find_entry( 	
	PVOID  	BaseAddress,
	LDR_RESOURCE_INFO *  	info,
	ULONG  	level,
	PVOID *  	ret,
	int  	want_dir 
) 		
{
    ULONG size;
    PVOID root;
    PIMAGE_RESOURCE_DIRECTORY resdirptr;
    USHORT list[9];  /* list of languages to try */
    int i, pos = 0;
    LCID user_lcid, system_lcid;
	PVOID AlternateModule;
	NTSTATUS Status;
	KPROCESSOR_MODE RequestorMode;

    root = RtlImageDirectoryEntryToData( BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size );
	
	RequestorMode = KeGetPreviousMode();
	if(RequestorMode!=KernelMode)
	{
		AlternateModule = LdrLoadAlternateResourceModule(BaseAddress, NULL);
		if(AlternateModule)
		{
			Status = find_entry(AlternateModule,
								info,
								level,
								ret,
								want_dir);
			if(NT_SUCCESS(Status))
			{
				return Status;
			}
		}
	}
	
    if (!root) 
		return STATUS_RESOURCE_DATA_NOT_FOUND;
    if (size < sizeof(*resdirptr)) 
		return STATUS_RESOURCE_DATA_NOT_FOUND;
    resdirptr = root;

    if (!level--) 
		goto done;
    if (!(*ret = LdrpSearchResourceSection_U_by_name( resdirptr, (LPCWSTR)info->Type, root, want_dir || level )))
        return STATUS_RESOURCE_TYPE_NOT_FOUND;
    if (!level--) 
		return STATUS_SUCCESS;

    resdirptr = *ret;
    if (!(*ret = LdrpSearchResourceSection_U_by_name( resdirptr, (LPCWSTR)info->Name, root, want_dir || level )))
        return STATUS_RESOURCE_NAME_NOT_FOUND;
    if (!level--) 
		return STATUS_SUCCESS;
    if (level) 
		return STATUS_INVALID_PARAMETER;  /* level > 3 */

    /* 1. specified language */
    pos = push_language( list, pos, (WORD)info->Language );

    /* 2. specified language with neutral sublanguage */
    pos = push_language( list, pos, MAKELANGID( PRIMARYLANGID(info->Language), SUBLANG_NEUTRAL ) );

    /* 3. neutral language with neutral sublanguage */
    pos = push_language( list, pos, MAKELANGID( LANG_NEUTRAL, SUBLANG_NEUTRAL ) );

    /* if no explicitly specified language, try some defaults */
    if (PRIMARYLANGID(info->Language) == LANG_NEUTRAL)
    {
        /* user defaults, unless SYS_DEFAULT sublanguage specified  */
        if (SUBLANGID(info->Language) != SUBLANG_SYS_DEFAULT)
        {
            /* 4. current thread locale language */
            pos = push_language( list, pos, LANGIDFROMLCID(NtCurrentTeb()->CurrentLocale) );

            if (NT_SUCCESS(NtQueryDefaultLocale(TRUE, &user_lcid)))
            {
                /* 5. user locale language */
                pos = push_language( list, pos, LANGIDFROMLCID(user_lcid) );

                /* 6. user locale language with neutral sublanguage  */
                pos = push_language( list, pos, MAKELANGID( PRIMARYLANGID(user_lcid), SUBLANG_NEUTRAL ) );
            }
        }

        /* now system defaults */

        if (NT_SUCCESS(NtQueryDefaultLocale(FALSE, &system_lcid)))
        {
            /* 7. system locale language */
            pos = push_language( list, pos, LANGIDFROMLCID( system_lcid ) );

            /* 8. system locale language with neutral sublanguage */
            pos = push_language( list, pos, MAKELANGID( PRIMARYLANGID(system_lcid), SUBLANG_NEUTRAL ) );
        }

        /* 9. English */
        pos = push_language( list, pos, MAKELANGID( LANG_ENGLISH, SUBLANG_DEFAULT ) );
    }

    resdirptr = *ret;
    for (i = 0; i < pos; i++)
        if ((*ret = LdrpSearchResourceSection_U_by_id( resdirptr, list[i], root, want_dir ))) return STATUS_SUCCESS;

    /* if no explicitly specified language, return the first entry */
    if (PRIMARYLANGID(info->Language) == LANG_NEUTRAL)
    {
        if ((*ret = find_first_entry( resdirptr, root, want_dir ))) return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_LANG_NOT_FOUND;

done:
    *ret = resdirptr;
    return STATUS_SUCCESS;
}

NTSTATUS 
NTAPI 
LdrFindResource_U( 	
	PVOID  	BaseAddress,
	PLDR_RESOURCE_INFO  ResourceInfo,
	ULONG  	Level,
	PIMAGE_RESOURCE_DATA_ENTRY *  ResourceDataEntry 
) 		
{
    PVOID res;
    NTSTATUS status = STATUS_SUCCESS;

    try
    {
        if (ResourceInfo)
        {
            DbgPrint( "module %p type %lx name %lx lang %04lx level %lu\n",
                     BaseAddress, ResourceInfo->Type, 
                     Level > 1 ? ResourceInfo->Name : 0,
                     Level > 2 ? ResourceInfo->Language : 0, Level );
        }

        status = find_entry( BaseAddress, ResourceInfo, Level, &res, FALSE );
        if (NT_SUCCESS(status))
            *ResourceDataEntry = res;
    }
    except (EXCEPTION_EXECUTE_HANDLER) 
    {
        status = 0x00000001;
    }
    return status;
}

NTSTATUS
LdrFindResourceEx_U(
    IN ULONG Flags,
    IN PVOID DllHandle,
    IN const ULONG_PTR* ResourceIdPath,
    IN ULONG ResourceIdPathLength,
    OUT PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry
    )

/*++

Routine Description:

    This function locates the address of the specified resource in the
    specified DLL and returns its address.

Arguments:
    Flags -
        LDRP_FIND_RESOURCE_DIRECTORY
        searching for a resource directory, otherwise the caller is
        searching for a resource data entry.

        LDR_FIND_RESOURCE_LANGUAGE_EXACT
        searching for a resource with, and only with, the language id
        specified in ResourceIdPath, otherwise the caller wants the routine
        to come up with default when specified langid is not found.

        LDR_FIND_RESOURCE_LANGUAGE_REDIRECT_VERSION
        searching for a resource version in both main and alternative
        module paths

    DllHandle - Supplies a handle to the image file that the resource is
        contained in.

    ResourceIdPath - Supplies a pointer to an array of 32-bit resource
        identifiers.  Each identifier is either an integer or a pointer
        to a STRING structure that specifies a resource name.  The array
        is used to traverse the directory structure contained in the
        resource section in the image file specified by the DllHandle
        parameter.

    ResourceIdPathLength - Supplies the number of elements in the
        ResourceIdPath array.

    ResourceDataEntry - Supplies a pointer to a variable that will
        receive the address of the resource data entry in the resource
        data section of the image file specified by the DllHandle
        parameter.
--*/

{
    RTL_PAGED_CODE();

    return LdrpSearchResourceSection_U(
      DllHandle,
      ResourceIdPath,
      ResourceIdPathLength,
      Flags,
      (PVOID *)ResourceDataEntry
      );
}



NTSTATUS
LdrFindResourceDirectory_U(
    IN PVOID DllHandle,
    IN const ULONG_PTR* ResourceIdPath,
    IN ULONG ResourceIdPathLength,
    OUT PIMAGE_RESOURCE_DIRECTORY *ResourceDirectory
    )

/*++

Routine Description:

    This function locates the address of the specified resource directory in
    specified DLL and returns its address.

Arguments:

    DllHandle - Supplies a handle to the image file that the resource
        directory is contained in.

    ResourceIdPath - Supplies a pointer to an array of 32-bit resource
        identifiers.  Each identifier is either an integer or a pointer
        to a STRING structure that specifies a resource name.  The array
        is used to traverse the directory structure contained in the
        resource section in the image file specified by the DllHandle
        parameter.

    ResourceIdPathLength - Supplies the number of elements in the
        ResourceIdPath array.

    ResourceDirectory - Supplies a pointer to a variable that will
        receive the address of the resource directory specified by
        ResourceIdPath in the resource data section of the image file
        the DllHandle parameter.
--*/

{
    RTL_PAGED_CODE();

    return LdrpSearchResourceSection_U(
      DllHandle,
      ResourceIdPath,
      ResourceIdPathLength,
      LDRP_FIND_RESOURCE_DIRECTORY,                 // Look for a directory node
      (PVOID *)ResourceDirectory
      );
}


LONG
LdrpCompareResourceNames_U(
    IN ULONG_PTR ResourceName,
    IN const IMAGE_RESOURCE_DIRECTORY* ResourceDirectory,
    IN const IMAGE_RESOURCE_DIRECTORY_ENTRY* ResourceDirectoryEntry
    )
{
    LONG li;
    PIMAGE_RESOURCE_DIR_STRING_U ResourceNameString;

    if (ResourceName & LDR_RESOURCE_ID_NAME_MASK) {
        if (!ResourceDirectoryEntry->NameIsString) {
            return( -1 );
            }

        ResourceNameString = (PIMAGE_RESOURCE_DIR_STRING_U)
            ((PCHAR)ResourceDirectory + ResourceDirectoryEntry->NameOffset);

        li = wcsncmp( (LPWSTR)ResourceName,
            ResourceNameString->NameString,
            ResourceNameString->Length
          );

        if (!li && wcslen((PWSTR)ResourceName) != ResourceNameString->Length) {
       return( 1 );
       }

   return(li);
        }
    else {
        if (ResourceDirectoryEntry->NameIsString) {
            return( 1 );
            }

        return( (ULONG)(ResourceName - ResourceDirectoryEntry->Name) );
        }
}

PVOID
LdrGetAlternateResourceModuleHandle(
    IN PVOID Module
    )
/*++

Routine Description:

    This function gets the alternate resource module from the table
    containing the handle.

Arguments:

    Module - Module of which alternate resource module needs to loaded.

Return Value:

   Handle of the alternate resource module.

--*/

{
    ULONG ModuleIndex;

    for (ModuleIndex = 0;
         ModuleIndex < AlternateResourceModuleCount;
         ModuleIndex++ ){
        if (AlternateResourceModules[ModuleIndex].ModuleBase ==
            Module){
            return AlternateResourceModules[ModuleIndex].AlternateModule;
        }
    }
    return NULL;
}

BOOLEAN
LdrpSetAlternateResourceModuleHandle(
    IN PVOID Module,
    IN PVOID AlternateModule
    )

/*++

Routine Description:

    This function records the handle of the base module and alternate
    resource module in an array.

Arguments:

    Module - The handle of the base module.
    AlternateModule - The handle of the alternate resource module

Return Value:

    TBD.

--*/

{
    PALT_RESOURCE_MODULE NewModules;

    if (AlternateResourceModules == NULL){
        //
        //  Allocate memory of initial size MEMBLOCKSIZE.
        //
        NewModules = ExAllocatePoolWithTag(PagedPool, 
										   RESMODSIZE * MEMBLOCKSIZE, 
										   0x69507472u);
		/*RtlAllocateHeap(
                        RtlProcessHeap(),
                        HEAP_ZERO_MEMORY,
                        RESMODSIZE * MEMBLOCKSIZE);*/
        if (!NewModules){
            return FALSE;
            }
        AlternateResourceModules = NewModules;
        AltResMemBlockCount = MEMBLOCKSIZE;
        }
    else
    if (AlternateResourceModuleCount >= AltResMemBlockCount ){
        /*
		//
        //  ReAllocate another chunk of memory.
        //
        NewModules = RtlReAllocateHeap(
                        RtlProcessHeap(),
                        0,
                        AlternateResourceModules,
                        (AltResMemBlockCount + MEMBLOCKSIZE) * RESMODSIZE
                        );
*/
		NewModules = ExAllocatePoolWithTag(PagedPool, 
										  (AltResMemBlockCount + MEMBLOCKSIZE) * RESMODSIZE, 
										  0x69507472u);
        if (!NewModules){
            return FALSE;
            }
        AlternateResourceModules = NewModules;
        AltResMemBlockCount += MEMBLOCKSIZE;
        }

    AlternateResourceModules[AlternateResourceModuleCount].ModuleBase = Module;
    AlternateResourceModules[AlternateResourceModuleCount].AlternateModule = AlternateModule;



    AlternateResourceModuleCount++;

    return TRUE;

}

BOOLEAN 
NTAPI
LdrAlternateResourcesEnabled(void)
{
  if ( (!UILangId || ImpersonateLangId || NtCurrentTeb()->IsImpersonating) && ZwQueryDefaultUILanguage(&UILangId) >= 0 )
    ImpersonateLangId = NtCurrentTeb()->IsImpersonating != 0 ? UILangId : 0;
  return UILangId && (InstallLangId || ZwQueryInstallUILanguage(&InstallLangId) >= 0);
}

PLDR_DATA_TABLE_ENTRY 
LdrpKrnGetDataTableEntry(PVOID ModuleBase)
{
  PKTHREAD thread; // esi@1
  PLDR_DATA_TABLE_ENTRY entry; // ebx@1
  PLDR_DATA_TABLE_ENTRY result; // eax@2
  PLDR_DATA_TABLE_ENTRY SizeOfImage; // eax@3
  PVOID DllBase; // ecx@4

  thread = KeGetCurrentThread();
  entry = NULL;
  if ( thread )
  {
    --thread->WaitTime;
    ExAcquireResourceSharedLite(&PsLoadedModuleResource, 1);
    SizeOfImage = (PLDR_DATA_TABLE_ENTRY)PsLoadedModuleList.Flink;
    while ( 1 )
    {
      DllBase = SizeOfImage->DllBase;
      if ( ModuleBase >= DllBase && (PCHAR)ModuleBase < (PCHAR)DllBase + SizeOfImage->SizeOfImage )
        break;
      SizeOfImage = (PLDR_DATA_TABLE_ENTRY)SizeOfImage->InLoadOrderLinks.Flink;
      if ( (LIST_ENTRY *)SizeOfImage == &PsLoadedModuleList )
        goto LABEL_9;
    }
    entry = SizeOfImage;
LABEL_9:
    ExReleaseResourceLite(&PsLoadedModuleResource);
    thread->WaitTime;
    if ( !thread->WaitTime
      && (KAPC_STATE *)thread->ApcState.ApcListHead[0].Flink != &thread->ApcState
      && !thread->WaitTime )
      KiCheckForKernelApcDelivery();
    result = entry;
  }
  else
  {
    result = NULL;
  }
  return result;
}

PVOID
NTAPI
LdrLoadAlternateResourceModuleEx(
	IN LANGID CustomLangId,
    IN PVOID Module,
    IN LPCWSTR PathToAlternateModule OPTIONAL
    )

/*++

Routine Description:

    This function does the acutally loading into memory of the alternate
    resource module, or loads from the table if it was loaded before.

Arguments:

    Module - The handle of the base module.
    PathToAlternateModule - Optional path from which module is being loaded.

Return Value:

    Handle to the alternate resource module.

--*/

{
    PVOID AlternateModule, DllBase;
    PLDR_DATA_TABLE_ENTRY Entry;
    HANDLE FileHandle, MappingHandle;
    PIMAGE_NT_HEADERS NtHeaders;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING AltDllName;
    PVOID FreeBuffer;
    LPWSTR BaseDllName, p;
    WCHAR DllPathName[DOS_MAX_PATH_LENGTH];
    ULONG DllPathNameLength, BaseDllNameLength, CopyCount;
    ULONG Digit;
    int i, RetryCount;
    WCHAR AltModulePath[DOS_MAX_PATH_LENGTH];
    WCHAR AltModulePathMUI[DOS_MAX_PATH_LENGTH];
    WCHAR AltModulePathFallback[DOS_MAX_PATH_LENGTH];
    IO_STATUS_BLOCK IoStatusBlock;
    RTL_RELATIVE_NAME_U RelativeName;
    SIZE_T ViewSize;
    LARGE_INTEGER SectionOffset;
    WCHAR LangIdDir[6];
    UNICODE_STRING AltModulePathList[4];
    UNICODE_STRING NtSystemRoot;
	UNICODE_STRING LocaleName;
	PVOID Object;

    //ExAcquireResourceSharedLite(&PsLoadedModuleResource,1);
	try{
    AlternateModule = LdrGetAlternateResourceModuleHandle(Module);
	
	MappingHandle = NULL;
	
	if(!CustomLangId)
	{
		if ( (!UILangId || ImpersonateLangId || NtCurrentTeb()->IsImpersonating) && ZwQueryDefaultUILanguage(&UILangId) >= 0 )
			ImpersonateLangId = NtCurrentTeb()->IsImpersonating != 0 ? UILangId : 0;
		CustomLangId = UILangId;
	}
	
	//AlternateModule = LdrGetAlternateResourceModuleHandle(Module, CustomLangId);
    if (AlternateModule == NO_ALTERNATE_RESOURCE_MODULE){
        //
        //  We tried to load this module before but failed. Don't try
        //  again in the future.
        //
		DbgPrint("LdrGetAlternateResourceModuleHandle from LdrLoadAlternateResourceModuleEx failed to get AlternateModule\n");		
		//ExReleaseResourceLite(&PsLoadedModuleResource);
        //RtlLeaveCriticalSection(
        //    (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
        return NULL;
        }
    else if (AlternateModule > 0){
        //
        //  We found the previously loaded match
        //
		DbgPrint("LdrGetAlternateResourceModuleHandle from LdrLoadAlternateResourceModuleEx success to get AlternateModule\n");		
		//ExReleaseResourceLite(&PsLoadedModuleResource);		
       // RtlLeaveCriticalSection(
        //    (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
        return AlternateModule;
        }

    if (ARGUMENT_PRESENT(PathToAlternateModule)){
        //
        //  Caller suplied path.
        //

        CopyCount = wcslen(PathToAlternateModule);

        for (p = (LPWSTR) PathToAlternateModule + CopyCount;
             p > PathToAlternateModule;
             p--){
            if (*(p-1) == L'\\'){
                break;
                }
            }

        if (p == PathToAlternateModule){
			DbgPrint("PathToAlternateModule from LdrLoadAlternateResourceModuleEx failed\n");				
            goto error_exit;
            }

        DllPathNameLength = (ULONG)(p - PathToAlternateModule) * sizeof(WCHAR);

        RtlCopyMemory(
            DllPathName,
            PathToAlternateModule,
            DllPathNameLength
            );

        BaseDllName = p ;
        BaseDllNameLength = CopyCount * sizeof(WCHAR) - DllPathNameLength;
        }
		
    else{
        //
        //  Try to get full dll path from Ldr data table.
        //
        /*Status = LdrFindEntryForAddress(Module, &Entry);		
	
		
        if (!NT_SUCCESS( Status )){
			DbgPrint("LdrFindEntryForAddress from LdrLoadAlternateResourceModuleEx failed, Status: %08x\n", Status);			
            goto error_exit;
            }*/
			
		Entry = LdrpKrnGetDataTableEntry(Module);
		
		if(!Entry)
		{
			DbgPrint("LdrpKrnGetDataTableEntry from LdrLoadAlternateResourceModuleEx failed\n");			
            goto error_exit;
		}

        DllPathNameLength = Entry->FullDllName.Length -
                            Entry->BaseDllName.Length;		

        RtlCopyMemory(
            DllPathName,
            Entry->FullDllName.Buffer,
            DllPathNameLength);
			
		DbgPrint("DllBaseName is %ws\n",Entry->BaseDllName.Buffer);

        BaseDllName = Entry->BaseDllName.Buffer;
        BaseDllNameLength = Entry->BaseDllName.Length;
        }

    DllPathName[DllPathNameLength / sizeof(WCHAR)] = UNICODE_NULL;

    //
    //  Generate the langid directory like "0804\"
    //
    if (!UILangId){
        Status = ZwQueryDefaultUILanguage( &UILangId );
        if (!NT_SUCCESS( Status )) {
			DbgPrint("NtQueryDefaultUILanguage from LdrLoadAlternateResourceModuleEx failed, Status: %08x\n", Status);				
            goto error_exit;
            }
        }

    CopyCount = 0;
    for (i = 12; i >= 0; i -= 4){
        Digit = ((CustomLangId >> i) & 0xF);
        if (Digit >= 10){
            LangIdDir[CopyCount++] = (WCHAR) (Digit - 10 + L'A');
            }
        else{
            LangIdDir[CopyCount++] = (WCHAR) (Digit + L'0');
            }
        }

    LangIdDir[CopyCount++] = L'\\';
    LangIdDir[CopyCount++] = UNICODE_NULL;

    //
    //  Generate the first path c:\winnt\system32\mui\0804\ntdll.dll.mui
    //
    AltModulePathList[1].Buffer = AltModulePath;
    AltModulePathList[1].Length = 0;
    AltModulePathList[1].MaximumLength = sizeof(AltModulePath);

    RtlAppendUnicodeToString(&AltModulePathList[1], DllPathName);
    RtlAppendUnicodeToString(&AltModulePathList[1], L"mui\\");
    RtlAppendUnicodeToString(&AltModulePathList[1], LangIdDir);
    RtlAppendUnicodeToString(&AltModulePathList[1], BaseDllName);
	
	DbgPrint("DllName: %ws\n", AltModulePathList[1].Buffer);	

    //
    //  Generate the first path c:\winnt\system32\mui\0804\ntdll.dll
    //
    AltModulePathList[0].Buffer = AltModulePathMUI;
    AltModulePathList[0].Length = 0;
    AltModulePathList[0].MaximumLength = sizeof(AltModulePathMUI);

    RtlCopyUnicodeString(&AltModulePathList[0], &AltModulePathList[1]);
    RtlAppendUnicodeToString(&AltModulePathList[0], L".mui");
	
	DbgPrint("DllMUIName: %ws\n", AltModulePathList[0].Buffer);
	
	//
    //  Generate the first path c:\winnt\system32\en-US\ntdll.dll
    //
    AltModulePathList[2].Buffer = AltModulePath;
    AltModulePathList[2].Length = 0;
    AltModulePathList[2].MaximumLength = sizeof(AltModulePath);
	
	//RtlLCIDToCultureName(CustomLangId,&LocaleName);

    RtlAppendUnicodeToString(&AltModulePathList[2], DllPathName);
    RtlAppendUnicodeToString(&AltModulePathList[2], L"en-US");
	RtlAppendUnicodeToString(&AltModulePathList[2], L"\\");
    RtlAppendUnicodeToString(&AltModulePathList[2], BaseDllName);
    RtlAppendUnicodeToString(&AltModulePathList[2], L".mui");
	
	DbgPrint("DllCultureName: %ws\n", AltModulePathList[2].Buffer);

    //
    //  Generate path c:\winnt\mui\fallback\0804\foo.exe.mui
    //
    AltModulePathList[3].Buffer = AltModulePathFallback;
    AltModulePathList[3].Length = 0;
    AltModulePathList[3].MaximumLength = sizeof(AltModulePathFallback);

    RtlInitUnicodeString(&NtSystemRoot, SharedUserData->NtSystemRoot);
    RtlAppendUnicodeStringToString(&AltModulePathList[3], &NtSystemRoot);
    RtlAppendUnicodeToString(&AltModulePathList[3], L"\\mui\\fallback\\");
    RtlAppendUnicodeToString(&AltModulePathList[3], LangIdDir);
    RtlAppendUnicodeToString(&AltModulePathList[3], BaseDllName);
    RtlAppendUnicodeToString(&AltModulePathList[3], L".mui");
	
	DbgPrint("DllFallbackPath: %ws\n", AltModulePathList[3].Buffer);

    //
    //  Try name with .mui extesion first.
    //
    RetryCount = 2;
    while (RetryCount < sizeof(AltModulePathList)/sizeof(UNICODE_STRING)){		
		 FreeBuffer = AltModulePathList[RetryCount].Buffer;
			
        InitializeObjectAttributes(
            &ObjectAttributes,
            &AltModulePathList[RetryCount],
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL
            );

        Status = ZwCreateFile(
                &FileHandle,
               (ACCESS_MASK) GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES,                
				&ObjectAttributes,
                &IoStatusBlock,
                NULL,
                0L,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                FILE_OPEN,
                0L,
                NULL,
                0L
                );						
				
		DbgPrint("NtCreateFile Status: %lx\n", Status);

        RtlFreeHeap(RtlProcessHeap(), 0, FreeBuffer);

        if (NT_SUCCESS( Status )){
            break;
            }
        if (Status != STATUS_OBJECT_NAME_NOT_FOUND && RetryCount == 0) {
            //
            //  Error other than the file name with .mui not found.
            //  Most likely directory is missing.  Skip file name w/o .mui
            //  and goto fallback directory.
            //
            RetryCount++;
            }

        RetryCount++;
        }

    Status = ZwCreateSection(
                &MappingHandle,
                STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ,
                NULL,
                NULL,
                PAGE_WRITECOPY,
                SEC_COMMIT,
                FileHandle
                );

    if (!NT_SUCCESS( Status )){
		DbgPrint("NtCreateSection from LdrLoadAlternateResourceModuleEx failed, Status: %08x\n", Status);			
        goto error_exit;
        }

    ZwClose( FileHandle );

    SectionOffset.LowPart = 0;
    SectionOffset.HighPart = 0;
    ViewSize = 0;
    DllBase = NULL;
	
	Status = ZwMapViewOfSection(
                MappingHandle,
                NtCurrentProcess(),
                &DllBase,
                0L,
                0L,
                &SectionOffset,
                &ViewSize,
                ViewShare,
                0L,
                PAGE_WRITECOPY
                );
				
	ZwClose( MappingHandle );
	
	if (!NT_SUCCESS( Status ))
	{
		DbgPrint("ObReferenceObjectByHandle from LdrLoadAlternateResourceModuleEx failed, Status: %08x\n", Status);			
        goto error_exit;
    }

    NtHeaders = RtlImageNtHeader( DllBase );
    if (!NtHeaders) {
        ZwUnmapViewOfSection(NtCurrentProcess(), (PVOID) DllBase);
		DbgPrint("RtlImageNtHeader from LdrLoadAlternateResourceModuleEx failed, is not NtHeader\n");			
        goto error_exit;
        }

    AlternateModule = (HANDLE)((ULONG_PTR)DllBase | 0x00000001);

    //
    //  Disable version check now to make testing with an earlier
    //  localized version easier.
    //
//    if(!LdrpVerifyAlternateResourceModule(Module, AlternateModule)){
//	 NtUnmapViewOfSection(NtCurrentProcess(), (PVOID) DllBase);
//	 goto error_exit;
//	 }


    LdrpSetAlternateResourceModuleHandle(Module, AlternateModule);
	//ExReleaseResourceLite(&PsLoadedModuleResource);
    //RtlLeaveCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
    return AlternateModule;
	
	//return NULL;
error_exit:
	LdrpSetAlternateResourceModuleHandle(Module, NO_ALTERNATE_RESOURCE_MODULE);
	return NULL;
	//ExReleaseResourceLite(&PsLoadedModuleResource);	
    //RtlLeaveCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
	}except(EXCEPTION_EXECUTE_HANDLER){	
    return NULL;
	}
}

PVOID
NTAPI
LdrLoadAlternateResourceModule(
    IN PVOID Module,
    IN LPCWSTR PathToAlternateModule OPTIONAL
    )
{
	return LdrLoadAlternateResourceModuleEx(0, Module, PathToAlternateModule);
}

// Language ids are 16bits so any value with any bits
// set above 16 should be ok, and this value only has
// to fit in a ULONG_PTR. 0x10000 should be sufficient.
// The value used is actually 0xFFFF regardless of 32bit or 64bit,
// I guess assuming this is not an actual langid, which it isn't,
// due to the relatively small number of languages, around 70.
#define  USE_FIRSTAVAILABLE_LANGID   (0xFFFFFFFF & ~LDR_RESOURCE_ID_NAME_MASK)

NTSTATUS
LdrpSearchResourceSection_U(
    IN PVOID DllHandle,
    IN const ULONG_PTR* ResourceIdPath,
    IN ULONG ResourceIdPathLength,
    IN ULONG Flags,
    OUT PVOID *ResourceDirectoryOrData
    )

/*++

Routine Description:

    This function locates the address of the specified resource in the
    specified DLL and returns its address.

Arguments:

    DllHandle - Supplies a handle to the image file that the resource is
        contained in.

    ResourceIdPath - Supplies a pointer to an array of 32-bit resource
        identifiers.  Each identifier is either an integer or a pointer
        to a null terminated string (PSZ) that specifies a resource
        name.  The array is used to traverse the directory structure
        contained in the resource section in the image file specified by
        the DllHandle parameter.

    ResourceIdPathLength - Supplies the number of elements in the
        ResourceIdPath array.

    Flags -
        LDRP_FIND_RESOURCE_DIRECTORY
        searching for a resource directory, otherwise the caller is
        searching for a resource data entry.

        LDR_FIND_RESOURCE_LANGUAGE_EXACT
        searching for a resource with, and only with, the language id
        specified in ResourceIdPath, otherwise the caller wants the routine
        to come up with default when specified langid is not found.

        LDR_FIND_RESOURCE_LANGUAGE_REDIRECT_VERSION
        searching for a resource version in main and alternative
        modules paths

    FindDirectoryEntry - Supplies a boolean that is TRUE if caller is
        searching for a resource directory, otherwise the caller is
        searching for a resource data entry.

    ExactLangMatchOnly - Supplies a boolean that is TRUE if caller is
        searching for a resource with, and only with, the language id
        specified in ResourceIdPath, otherwise the caller wants the routine
        to come up with default when specified langid is not found.

    ResourceDirectoryOrData - Supplies a pointer to a variable that will
        receive the address of the resource directory or data entry in
        the resource data section of the image file specified by the
        DllHandle parameter.
--*/

{
    NTSTATUS Status;
    PIMAGE_RESOURCE_DIRECTORY LanguageResourceDirectory, ResourceDirectory, TopResourceDirectory;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirEntLow;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirEntMiddle;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirEntHigh;
    PIMAGE_RESOURCE_DATA_ENTRY ResourceEntry;
    USHORT n, half;
    LONG dir;
    ULONG size;
    ULONG_PTR ResourceIdRetry;
    ULONG RetryCount;
    LANGID NewLangId;
    const ULONG_PTR* IdPath = ResourceIdPath;
    ULONG IdPathLength = ResourceIdPathLength;
    BOOLEAN fIsNeutral = FALSE;
    LANGID GivenLanguage;
	PVOID AlternateModule;
	KPROCESSOR_MODE RequestorMode;

    RTL_PAGED_CODE();

    try {
        TopResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
            RtlImageDirectoryEntryToData(DllHandle,
                                         TRUE,
                                         IMAGE_DIRECTORY_ENTRY_RESOURCE,
                                         &size
                                         );
        if (!TopResourceDirectory) {
            return( STATUS_RESOURCE_DATA_NOT_FOUND );
        }
		/*
		RequestorMode = KeGetPreviousMode();
		if(RequestorMode!=KernelMode)
		{
			AlternateModule = LdrLoadAlternateResourceModule(DllHandle, NULL);
			if(AlternateModule)
			{
				Status = LdrpSearchResourceSection_U(AlternateModule,
													 ResourceIdPath,
													 ResourceIdPathLength,
													 Flags,
													 ResourceDirectoryOrData);
				if(NT_SUCCESS(Status))
				{
					return Status;
				}
			}
		}*/
		
        ResourceDirectory = TopResourceDirectory;
        ResourceIdRetry = USE_FIRSTAVAILABLE_LANGID;
        RetryCount = 0;
        ResourceEntry = NULL;
        LanguageResourceDirectory = NULL;
        while (ResourceDirectory != NULL && ResourceIdPathLength--) {
            //
            // If search path includes a language id, then attempt to
            // match the following language ids in this order:
            //
            //   (0)  use given language id
            //   (1)  use primary language of given language id
            //   (2)  use id 0  (neutral resource)
            //   (4)  use user UI language
            //
            // If the PRIMARY language id is ZERO, then ALSO attempt to
            // match the following language ids in this order:
            //
            //   (3)  use thread language id for console app
            //   (4)  use user UI language
            //   (5)  use lang id of TEB for windows app if it is different from user locale
            //   (6)  use UI lang from exe resource
            //   (7)  use primary UI lang from exe resource
            //   (8)  use Install Language
            //   (9)  use lang id from user's locale id
            //   (10)  use primary language of user's locale id
            //   (11) use lang id from system default locale id
            //   (12) use lang id of system default locale id
            //   (13) use primary language of system default locale id
            //   (14) use US English lang id
            //   (15) use any lang id that matches requested info
            //
            if (ResourceIdPathLength == 0 && IdPathLength == 3) {
                LanguageResourceDirectory = ResourceDirectory;
                }

            if (LanguageResourceDirectory != NULL) {
                GivenLanguage = (LANGID)IdPath[ 2 ];
                fIsNeutral = (PRIMARYLANGID( GivenLanguage ) == LANG_NEUTRAL);
TryNextLangId:
                switch( RetryCount++ ) {
                    case 0:     // Use given language id
                        NewLangId = GivenLanguage;
                        break;

                    case 1:     // Use primary language of given language id
                        NewLangId = PRIMARYLANGID( GivenLanguage );
                        break;

                    case 2:     // Use id 0  (neutral resource)
                        NewLangId = 0;
                        break;

                    case 3:     // Use user's default UI language
                        NewLangId = (LANGID)ResourceIdRetry;
                        break;

                    case 4:     // Use native UI language
                        if ( !fIsNeutral ) {
                            // Stop looking - Not in the neutral case
                            goto ReturnFailure;
                            break;
                        }
                        NewLangId = PsInstallUILanguageId;
                        break;

                    case 5:     // Use default system locale
                        NewLangId = LANGIDFROMLCID(PsDefaultSystemLocaleId);
                        break;

                    case 6:
                        // Use US English language
                        NewLangId = MAKELANGID( LANG_ENGLISH, SUBLANG_ENGLISH_US );
                        break;

                    case 7:     // Take any lang id that matches
                        NewLangId = USE_FIRSTAVAILABLE_LANGID;
                        break;

                    default:    // No lang ids to match
                        goto ReturnFailure;
                        break;
                }

                //
                // If looking for a specific language id and same as the
                // one we just looked up, then skip it.
                //
                if (NewLangId != USE_FIRSTAVAILABLE_LANGID &&
                    NewLangId == ResourceIdRetry
                   ) {
                    goto TryNextLangId;
                    }

                //
                // Try this new language Id
                //
                ResourceIdRetry = (ULONG_PTR)NewLangId;
                ResourceIdPath = &ResourceIdRetry;
                ResourceDirectory = LanguageResourceDirectory;
                }

            n = ResourceDirectory->NumberOfNamedEntries;
            ResourceDirEntLow = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ResourceDirectory+1);
            if (!(*ResourceIdPath & LDR_RESOURCE_ID_NAME_MASK)) { // No string(name),so we need ID
                ResourceDirEntLow += n;
                n = ResourceDirectory->NumberOfIdEntries;
                }

            if (!n) {
                ResourceDirectory = NULL;
                goto NotFound;  // Resource directory contains zero types or names or langID.
                }

            if (LanguageResourceDirectory != NULL &&
                *ResourceIdPath == USE_FIRSTAVAILABLE_LANGID
               ) {
                ResourceDirectory = NULL;
                ResourceIdRetry = ResourceDirEntLow->Name;
                ResourceEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                    ((PCHAR)TopResourceDirectory +
                            ResourceDirEntLow->OffsetToData
                    );

                break;
                }

            ResourceDirectory = NULL;
            ResourceDirEntHigh = ResourceDirEntLow + n - 1;
            while (ResourceDirEntLow <= ResourceDirEntHigh) {
                if ((half = (n >> 1)) != 0) {
                    ResourceDirEntMiddle = ResourceDirEntLow;
                    if (*(PUCHAR)&n & 1) {
                        ResourceDirEntMiddle += half;
                        }
                    else {
                        ResourceDirEntMiddle += half - 1;
                        }
                    dir = LdrpCompareResourceNames_U( *ResourceIdPath,
                                                      TopResourceDirectory,
                                                      ResourceDirEntMiddle
                                                    );
                    if (!dir) {
                        if (ResourceDirEntMiddle->DataIsDirectory) {
                            ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
                    ((PCHAR)TopResourceDirectory +
                                    ResourceDirEntMiddle->OffsetToDirectory
                                );
                            }
                        else {
                            ResourceDirectory = NULL;
                            ResourceEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                                ((PCHAR)TopResourceDirectory +
                                 ResourceDirEntMiddle->OffsetToData
                                );
                            }

                        break;
                        }
                    else {
                        if (dir < 0) {  // Order in the resource: Name, ID.
                            ResourceDirEntHigh = ResourceDirEntMiddle - 1;
                            if (*(PUCHAR)&n & 1) {
                                n = half;
                                }
                            else {
                                n = half - 1;
                                }
                            }
                        else {
                            ResourceDirEntLow = ResourceDirEntMiddle + 1;
                            n = half;
                            }
                        }
                    }
                else {
                    if (n != 0) {
                        dir = LdrpCompareResourceNames_U( *ResourceIdPath,
                          TopResourceDirectory,
                                                          ResourceDirEntLow
                                                        );
                        if (!dir) {   // find, or it fail to set ResourceDirectory so go to NotFound.
                            if (ResourceDirEntLow->DataIsDirectory) {
                                ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
                                    ((PCHAR)TopResourceDirectory +
                                        ResourceDirEntLow->OffsetToDirectory
                                    );
                                }
                            else {
                                ResourceEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                                    ((PCHAR)TopResourceDirectory +
                      ResourceDirEntLow->OffsetToData
                                    );
                                }
                            }
                        }

                    break;
                    }
                }

            ResourceIdPath++;
            }

        if (ResourceEntry != NULL && !(Flags & LDRP_FIND_RESOURCE_DIRECTORY)) {
            *ResourceDirectoryOrData = (PVOID)ResourceEntry;
            Status = STATUS_SUCCESS;
            }
        else
        if (ResourceDirectory != NULL && (Flags & LDRP_FIND_RESOURCE_DIRECTORY)) {
            *ResourceDirectoryOrData = (PVOID)ResourceDirectory;
            Status = STATUS_SUCCESS;
            }
        else {
NotFound:
            switch( IdPathLength - ResourceIdPathLength) {
                case 3:     Status = STATUS_RESOURCE_LANG_NOT_FOUND; break;
                case 2:     Status = STATUS_RESOURCE_NAME_NOT_FOUND; break;
                case 1:     Status = STATUS_RESOURCE_TYPE_NOT_FOUND; break;
                default:    Status = STATUS_INVALID_PARAMETER; break;
                }
            }

        if (Status == STATUS_RESOURCE_LANG_NOT_FOUND &&
            LanguageResourceDirectory != NULL
           ) {
            ResourceEntry = NULL;
            goto TryNextLangId;
ReturnFailure: ;
            Status = STATUS_RESOURCE_LANG_NOT_FOUND;
            }
        }
    except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        }

    return Status;
}


NTSTATUS
LdrEnumResources(
    IN PVOID DllHandle,
    IN const ULONG_PTR* ResourceIdPath,
    IN ULONG ResourceIdPathLength,
    IN OUT PULONG NumberOfResources,
    OUT PLDR_ENUM_RESOURCE_ENTRY Resources OPTIONAL
    )
{
    NTSTATUS Status;
    PIMAGE_RESOURCE_DIRECTORY TopResourceDirectory;
    PIMAGE_RESOURCE_DIRECTORY TypeResourceDirectory;
    PIMAGE_RESOURCE_DIRECTORY NameResourceDirectory;
    PIMAGE_RESOURCE_DIRECTORY LangResourceDirectory;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY TypeResourceDirectoryEntry;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY NameResourceDirectoryEntry;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY LangResourceDirectoryEntry;
    ULONG TypeDirectoryIndex, NumberOfTypeDirectoryEntries;
    ULONG NameDirectoryIndex, NumberOfNameDirectoryEntries;
    ULONG LangDirectoryIndex, NumberOfLangDirectoryEntries;
    BOOLEAN ScanTypeDirectory;
    BOOLEAN ScanNameDirectory;
    BOOLEAN ReturnThisResource;
    PIMAGE_RESOURCE_DIR_STRING_U ResourceNameString;
    ULONG_PTR TypeResourceNameOrId;
    ULONG_PTR NameResourceNameOrId;
    ULONG_PTR LangResourceNameOrId;
    PLDR_ENUM_RESOURCE_ENTRY ResourceInfo;
    PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry;
    ULONG ResourceIndex, MaxResourceIndex;
    ULONG Size;

    ResourceIndex = 0;
    if (!ARGUMENT_PRESENT( Resources )) {
        MaxResourceIndex = 0;
        }
    else {
        MaxResourceIndex = *NumberOfResources;
        }
    *NumberOfResources = 0;

    TopResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
        RtlImageDirectoryEntryToData( DllHandle,
                                      TRUE,
                                      IMAGE_DIRECTORY_ENTRY_RESOURCE,
                                      &Size
                                    );
    if (!TopResourceDirectory) {
        return STATUS_RESOURCE_DATA_NOT_FOUND;
        }

    TypeResourceDirectory = TopResourceDirectory;
    TypeResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(TypeResourceDirectory+1);
    NumberOfTypeDirectoryEntries = TypeResourceDirectory->NumberOfNamedEntries +
                                   TypeResourceDirectory->NumberOfIdEntries;
    TypeDirectoryIndex = 0;
    Status = STATUS_SUCCESS;
    for (TypeDirectoryIndex=0;
         TypeDirectoryIndex<NumberOfTypeDirectoryEntries;
         TypeDirectoryIndex++, TypeResourceDirectoryEntry++
        ) {
        if (ResourceIdPathLength > 0) {
            ScanTypeDirectory = LdrpCompareResourceNames_U( ResourceIdPath[ 0 ],
                                                            TopResourceDirectory,
                                                            TypeResourceDirectoryEntry
                                                          ) == 0;
            }
        else {
            ScanTypeDirectory = TRUE;
            }
        if (ScanTypeDirectory) {
            if (!TypeResourceDirectoryEntry->DataIsDirectory) {
                return STATUS_INVALID_IMAGE_FORMAT;
                }
            if (TypeResourceDirectoryEntry->NameIsString) {
                ResourceNameString = (PIMAGE_RESOURCE_DIR_STRING_U)
                    ((PCHAR)TopResourceDirectory + TypeResourceDirectoryEntry->NameOffset);

                TypeResourceNameOrId = (ULONG_PTR)ResourceNameString;
                }
            else {
                TypeResourceNameOrId = (ULONG_PTR)TypeResourceDirectoryEntry->Id;
                }

            NameResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
                ((PCHAR)TopResourceDirectory + TypeResourceDirectoryEntry->OffsetToDirectory);
            NameResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(NameResourceDirectory+1);
            NumberOfNameDirectoryEntries = NameResourceDirectory->NumberOfNamedEntries +
                                           NameResourceDirectory->NumberOfIdEntries;
            for (NameDirectoryIndex=0;
                 NameDirectoryIndex<NumberOfNameDirectoryEntries;
                 NameDirectoryIndex++, NameResourceDirectoryEntry++
                ) {
                if (ResourceIdPathLength > 1) {
                    ScanNameDirectory = LdrpCompareResourceNames_U( ResourceIdPath[ 1 ],
                                                                    TopResourceDirectory,
                                                                    NameResourceDirectoryEntry
                                                                  ) == 0;
                    }
                else {
                    ScanNameDirectory = TRUE;
                    }
                if (ScanNameDirectory) {
                    if (!NameResourceDirectoryEntry->DataIsDirectory) {
                        return STATUS_INVALID_IMAGE_FORMAT;
                        }

                    if (NameResourceDirectoryEntry->NameIsString) {
                        ResourceNameString = (PIMAGE_RESOURCE_DIR_STRING_U)
                            ((PCHAR)TopResourceDirectory + NameResourceDirectoryEntry->NameOffset);

                        NameResourceNameOrId = (ULONG_PTR)ResourceNameString;
                        }
                    else {
                        NameResourceNameOrId = (ULONG_PTR)NameResourceDirectoryEntry->Id;
                        }

                    LangResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
                        ((PCHAR)TopResourceDirectory + NameResourceDirectoryEntry->OffsetToDirectory);

                    LangResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(LangResourceDirectory+1);
                    NumberOfLangDirectoryEntries = LangResourceDirectory->NumberOfNamedEntries +
                                                   LangResourceDirectory->NumberOfIdEntries;
                    LangDirectoryIndex = 0;
                    for (LangDirectoryIndex=0;
                         LangDirectoryIndex<NumberOfLangDirectoryEntries;
                         LangDirectoryIndex++, LangResourceDirectoryEntry++
                        ) {
                        if (ResourceIdPathLength > 2) {
                            ReturnThisResource = LdrpCompareResourceNames_U( ResourceIdPath[ 2 ],
                                                                             TopResourceDirectory,
                                                                             LangResourceDirectoryEntry
                                                                           ) == 0;
                            }
                        else {
                            ReturnThisResource = TRUE;
                            }
                        if (ReturnThisResource) {
                            if (LangResourceDirectoryEntry->DataIsDirectory) {
                                return STATUS_INVALID_IMAGE_FORMAT;
                                }

                            if (LangResourceDirectoryEntry->NameIsString) {
                                ResourceNameString = (PIMAGE_RESOURCE_DIR_STRING_U)
                                    ((PCHAR)TopResourceDirectory + LangResourceDirectoryEntry->NameOffset);

                                LangResourceNameOrId = (ULONG_PTR)ResourceNameString;
                                }
                            else {
                                LangResourceNameOrId = (ULONG_PTR)LangResourceDirectoryEntry->Id;
                                }

                            ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)
                                    ((PCHAR)TopResourceDirectory + LangResourceDirectoryEntry->OffsetToData);

                            ResourceInfo = &Resources[ ResourceIndex++ ];
                            if (ResourceIndex <= MaxResourceIndex) {
                                ResourceInfo->Path[ 0 ].NameOrId = TypeResourceNameOrId;
                                ResourceInfo->Path[ 1 ].NameOrId = NameResourceNameOrId;
                                ResourceInfo->Path[ 2 ].NameOrId = LangResourceNameOrId;
                                ResourceInfo->Data = (PVOID)((ULONG_PTR)DllHandle + ResourceDataEntry->OffsetToData);
                                ResourceInfo->Size = ResourceDataEntry->Size;
                                ResourceInfo->Reserved = 0;
                                }
                            else {
                                Status = STATUS_INFO_LENGTH_MISMATCH;
                                }
                            }
                        }
                    }
                }
            }
        }

    *NumberOfResources = ResourceIndex;
    return Status;
}

