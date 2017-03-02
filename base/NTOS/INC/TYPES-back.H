

typedef struct _SCOPETABLE_ENTRY
{
  int EnclosingLevel;
  void *FilterFunc;
  void *HandlerFunc;
}SCOPETABLE_ENTRY, *PSCOPETABLE_ENTRY;

typedef struct _EH3_EXCEPTION_REGISTRATION
{
  struct _EH3_EXCEPTION_REGISTRATION *Next;
  PVOID ExceptionHandler;
  PSCOPETABLE_ENTRY ScopeTable;
  DWORD TryLevel;
}EH3_EXCEPTION_REGISTRATION, *PEH3_EXCEPTION_REGISTRATION;

typedef struct CPPEH_RECORD
{
  DWORD old_esp;
  EXCEPTION_POINTERS *exc_ptr;
  EH3_EXCEPTION_REGISTRATION registration;
}CPPEH_RECORD, *PCPPEH_RECORD;

typedef enum _KENLISTMENT_STATE
{
         KEnlistmentUninitialized = 0,
         KEnlistmentActive = 256,
         KEnlistmentPreparing = 257,
         KEnlistmentPrepared = 258,
         KEnlistmentInDoubt = 259,
         KEnlistmentCommitted = 260,
         KEnlistmentCommittedNotify = 261,
         KEnlistmentCommitRequested = 262,
         KEnlistmentAborted = 263,
         KEnlistmentDelegated = 264,
         KEnlistmentDelegatedDisconnected = 265,
         KEnlistmentPrePreparing = 266,
         KEnlistmentForgotten = 267,
         KEnlistmentRecovering = 268,
         KEnlistmentSavepointing = 269,
         KEnlistmentAborting = 270,
         KEnlistmentReadOnly = 271,
         KEnlistmentOutcomeUnavailable = 272,
         KEnlistmentOffline = 273,
         KEnlistmentPrePrepared = 274,
         KEnlistmentInitialized = 275
} KENLISTMENT_STATE;

typedef enum _KRESOURCEMANAGER_STATE
{
         KResourceManagerUninitialized = 0,
         KResourceManagerOffline = 1,
         KResourceManagerOnline = 2
} KRESOURCEMANAGER_STATE;

typedef struct _KENLISTMENT_HISTORY
{
     ULONG Notification;
     KENLISTMENT_STATE NewState;
} KENLISTMENT_HISTORY, *PKENLISTMENT_HISTORY;

typedef struct _KTMOBJECT_NAMESPACE_LINK
{
     PVOID Links;
     UCHAR Expired;
} KTMOBJECT_NAMESPACE_LINK, *PKTMOBJECT_NAMESPACE_LINK;

typedef enum 
{
         KKtmUninitialized = 0,
         KKtmInitialized = 1,
         KKtmRecovering = 2,
         KKtmOnline = 3,
         KKtmRecoveryFailed = 4,
         KKtmOffline = 5
} KTM_STATE;

typedef struct _KTMOBJECT_NAMESPACE
{
     RTL_AVL_TABLE Table;
     KMUTANT Mutex;
     WORD LinksOffset;
     WORD GuidOffset;
     UCHAR Expired;
} KTMOBJECT_NAMESPACE, *PKTMOBJECT_NAMESPACE;

typedef struct _CLS_LSN
{
     UINT64 ullOffset;
} CLS_LSN, *PCLS_LSN;

typedef struct _KTM
{
     ULONG cookie;
     KMUTANT Mutex;
     KTM_STATE State;
     KTMOBJECT_NAMESPACE_LINK NamespaceLink;
     GUID TmIdentity;
     ULONG Flags;
     ULONG VolatileFlags;
     UNICODE_STRING LogFileName;
     PFILE_OBJECT LogFileObject;
     PVOID MarshallingContext;
     PVOID LogManagementContext;
     KTMOBJECT_NAMESPACE Transactions;
     KTMOBJECT_NAMESPACE ResourceManagers;
     KMUTANT LsnOrderedMutex;
     LIST_ENTRY LsnOrderedList;
     LARGE_INTEGER CommitVirtualClock;
     FAST_MUTEX CommitVirtualClockMutex;
     CLS_LSN BaseLsn;
     CLS_LSN CurrentReadLsn;
     PVOID TmRmHandle;
     KEVENT LogFullNotifyEvent;
     WORK_QUEUE_ITEM CheckpointWorkItem;
     CLS_LSN CheckpointTargetLsn;
     WORK_QUEUE_ITEM LogFullCompletedWorkItem;
     ERESOURCE LogWriteResource;
     ULONG LogFlags;
     LONG LogFullStatus;
     LONG RecoveryStatus;
} KTM, *PKTM;

typedef struct _KRESOURCEMANAGER_COMPLETION_BINDING
{
     LIST_ENTRY NotificationListHead;
     PVOID Port;
     ULONG Key;
     PEPROCESS BindingProcess;
} KRESOURCEMANAGER_COMPLETION_BINDING, *PKRESOURCEMANAGER_COMPLETION_BINDING;

typedef struct _KRESOURCEMANAGER
{
     KEVENT NotificationAvailable;
     ULONG cookie;
     KRESOURCEMANAGER_STATE State;
     ULONG Flags;
     KMUTANT Mutex;
     KTMOBJECT_NAMESPACE_LINK NamespaceLink;
     GUID RmId;
     KQUEUE NotificationQueue;
     KMUTANT NotificationMutex;
     LIST_ENTRY EnlistmentHead;
     ULONG EnlistmentCount;
     LONG * NotificationRoutine;
     PVOID Key;
     LIST_ENTRY ProtocolListHead;
     LIST_ENTRY PendingPropReqListHead;
     LIST_ENTRY CRMListEntry;
     PKTM Tm;
     UNICODE_STRING Description;
     KTMOBJECT_NAMESPACE Enlistments;
     KRESOURCEMANAGER_COMPLETION_BINDING CompletionBinding;
} KRESOURCEMANAGER, *PKRESOURCEMANAGER;

typedef struct _KTMNOTIFICATION_PACKET // 0 elements, 0x0 bytes (sizeof)
{
	int value;
}KTMNOTIFICATION_PACKET, *PKTMNOTIFICATION_PACKET;

typedef struct _KENLISTMENT
{
     ULONG cookie;
     KTMOBJECT_NAMESPACE_LINK NamespaceLink;
     GUID EnlistmentId;
     KMUTANT Mutex;
     LIST_ENTRY NextSameTx;
     LIST_ENTRY NextSameRm;
     PKRESOURCEMANAGER ResourceManager;
     PKTRANSACTION Transaction;
     KENLISTMENT_STATE State;
     ULONG Flags;
     ULONG NotificationMask;
     PVOID Key;
     ULONG KeyRefCount;
     PVOID RecoveryInformation;
     ULONG RecoveryInformationLength;
     PVOID DynamicNameInformation;
     ULONG DynamicNameInformationLength;
     PKTMNOTIFICATION_PACKET FinalNotification;
     PVOID SupSubEnlistment;
     PVOID SupSubEnlHandle;
     PVOID SubordinateTxHandle;
     GUID CrmEnlistmentEnId;
     GUID CrmEnlistmentTmId;
     GUID CrmEnlistmentRmId;
     ULONG NextHistory;
     KENLISTMENT_HISTORY History[20];
} KENLISTMENT, *PKENLISTMENT;