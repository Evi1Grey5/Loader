#include "internals.h"

#if defined(DEBUG)
#include <stdio.h>
#include <string.h>

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

 #define DPRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILENAME__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )

#define mem_zero(dest,size) __stosb((PBYTE)dest,0,size)
#define mem_copy(dest,source,size) __movsb((PBYTE)dest,(PBYTE)source,size)
#define mem_set(dest,bt,size) __stosb((PBYTE)dest,bt,size)

typedef PVOID (NTAPI* TD_RtlAllocateHeap)(
    PVOID              HeapHandle,
    ULONG              Flags,
    SIZE_T             Size
);

typedef BOOL (WINAPI* TD_NtGetContextThread)(
    HANDLE             hThread,
    LPCONTEXT          lpContext
);

typedef PVOID  (NTAPI* TD_RtlFreeHeap)(
    PVOID              HeapHandle,
    ULONG              Flags,
    PVOID              BaseAddress
);

typedef NTSTATUS (NTAPI* TD_NtContinue)(
    PCONTEXT           ThreadContext,
    BOOLEAN            RaiseAlert
);

typedef NTSTATUS (NTAPI* TD_NtCreateSection) (
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

typedef NTSTATUS (NTAPI* TD_NtMapViewOfSection)(
    HANDLE             SectionHandle,
    HANDLE             ProcessHandle,
    PVOID              *BaseAddress,
    ULONG_PTR          ZeroBits,
    SIZE_T             CommitSize,
    PLARGE_INTEGER     SectionOffset,
    PSIZE_T            ViewSize,
    SECTION_INHERIT    InheritDisposition,
    ULONG              AllocationType,
    ULONG              Win32Protect
);

typedef NTSTATUS (NTAPI* TD_NtUnmapViewOfSection)(
    HANDLE             ProcessHandle,
    PVOID              BaseAddress
);

typedef NTSTATUS (NTAPI* TD_NtClose)(
    HANDLE handle
);

typedef NTSTATUS (NTAPI* TD_NtQueryObject)(
    HANDLE                   Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID                    ObjectInformation,
    ULONG                    ObjectInformationLength,
    PULONG                   ReturnLength

);

typedef LONG (NTAPI* TD_RtlCompareUnicodeString)(
    PUNICODE_STRING String1,
    PUNICODE_STRING String2,
    BOOLEAN         CaseInSensitive
);

typedef BOOLEAN (NTAPI* TD_RtlCreateUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR          SourceString
);

typedef enum HOOKAPI {
    ZwOpenSection,
    ZwMapViewOfSection,
    ZwClose,
    End
};

typedef struct _LL_WRAPPER {
    
    TD_RtlCompareUnicodeString pRtlCompareUnicodeString;
    TD_RtlCreateUnicodeString  pRtlCreateUnicodeString;
    TD_RtlAllocateHeap         pRtlAllocateHeap;
    TD_NtGetContextThread      pZwGetContextThread;
    TD_RtlFreeHeap             pRtlFreeHeap;
    TD_NtContinue              pZwContinue;
    TD_NtCreateSection         pZwCreateSection;
    TD_NtUnmapViewOfSection    pZwUnmapViewOfSection;

    ULONG_PTR                  pZwOpenSection;
    TD_NtMapViewOfSection      pZwMapViewOfSection;
    ULONG_PTR                  pZwClose;
    TD_NtQueryObject           pZwQueryObject;

    BYTE                       status;
    PVOID                      DllBase;
    HANDLE                     hSection;
    ULONG_PTR                  entrypoint;
    BOOL                       is_dll;
    
    UNICODE_STRING             Directory;
    UNICODE_STRING             Directory32;
    UNICODE_STRING             DllName;

} LL_WRAPPER, *PLL_WRAPPER;

