/* Begin from winternl.h */



#ifndef __STRING_DEFINED
#define __STRING_DEFINED
typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
  PCHAR  Buffer;
} STRING, *PSTRING;
#endif


          typedef struct _CURDIR {            // 2 elements, 0xC bytes (sizeof)
/*0x000*/     struct _UNICODE_STRING DosPath; // 3 elements, 0x8 bytes (sizeof)
/*0x008*/     VOID*        Handle;
          } CURDIR, *PCURDIR;

          typedef struct _RTL_DRIVE_LETTER_CURDIR { // 4 elements, 0x10 bytes (sizeof)
/*0x000*/     UINT16       Flags;
/*0x002*/     UINT16       Length;
/*0x004*/     ULONG32      TimeStamp;
/*0x008*/     struct _STRING DosPath;             // 3 elements, 0x8 bytes (sizeof)
          } RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;


#if _WIN64 || _Win64
          typedef struct _LDR_DATA_TABLE_ENTRY64 {                       // 24 elements, 0xE0 bytes (sizeof)
/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
/*0x030*/     VOID*        DllBase;
/*0x038*/     VOID*        EntryPoint;
/*0x040*/     ULONG32      SizeOfImage;
/*0x044*/     UINT8        _PADDING0_[0x4];
/*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
/*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
/*0x068*/     ULONG32      Flags;
/*0x06C*/     UINT16       LoadCount;
/*0x06E*/     UINT16       TlsIndex;
              union {                                                  // 2 elements, 0x10 bytes (sizeof)
/*0x070*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x10 bytes (sizeof)
                  struct {                                             // 2 elements, 0x10 bytes (sizeof)
/*0x070*/             VOID*        SectionPointer;
/*0x078*/             ULONG32      CheckSum;
/*0x07C*/             UINT8        _PADDING1_[0x4];
                  };
              };
              union {                                                  // 2 elements, 0x8 bytes (sizeof)
/*0x080*/         ULONG32      TimeDateStamp;
/*0x080*/         VOID*        LoadedImports;
              };
/*0x088*/     struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
/*0x090*/     VOID*        PatchInformation;
/*0x098*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x10 bytes (sizeof)
/*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x10 bytes (sizeof)
/*0x0B8*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x10 bytes (sizeof)
/*0x0C8*/     VOID*        ContextInformation;
/*0x0D0*/     UINT64       OriginalBase;
/*0x0D8*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
          } LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

          typedef struct _PEB_LDR_DATA64 {                          // 9 elements, 0x58 bytes (sizeof)
/*0x000*/     ULONG64      Length;
/*0x004*/     UINT8        Initialized;
/*0x005*/     UINT8        _PADDING0_[0x3];
/*0x008*/     VOID*        SsHandle;
/*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof)
/*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof)
/*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof)
/*0x040*/     VOID*        EntryInProgress;
/*0x048*/     UINT8        ShutdownInProgress;
/*0x049*/     UINT8        _PADDING1_[0x7];
/*0x050*/     VOID*        ShutdownThreadId;
          } PEB_LDR_DATA64, *PPEB_LDR_DATA64;

          typedef struct _RTL_USER_PROCESS_PARAMETERS64 {              // 30 elements, 0x400 bytes (sizeof)
/*0x000*/     ULONG32      MaximumLength;
/*0x004*/     ULONG32      Length;
/*0x008*/     ULONG32      Flags;
/*0x00C*/     ULONG32      DebugFlags;
/*0x010*/     VOID*        ConsoleHandle;
/*0x018*/     ULONG32      ConsoleFlags;
/*0x01C*/     UINT8        _PADDING0_[0x4];
/*0x020*/     VOID*        StandardInput;
/*0x028*/     VOID*        StandardOutput;
/*0x030*/     VOID*        StandardError;
/*0x038*/     struct _CURDIR CurrentDirectory;                       // 2 elements, 0x18 bytes (sizeof)
/*0x050*/     struct _UNICODE_STRING DllPath;                        // 3 elements, 0x10 bytes (sizeof)
/*0x060*/     struct _UNICODE_STRING ImagePathName;                  // 3 elements, 0x10 bytes (sizeof)
/*0x070*/     struct _UNICODE_STRING CommandLine;                    // 3 elements, 0x10 bytes (sizeof)
/*0x080*/     VOID*        Environment;
/*0x088*/     ULONG32      StartingX;
/*0x08C*/     ULONG32      StartingY;
/*0x090*/     ULONG32      CountX;
/*0x094*/     ULONG32      CountY;
/*0x098*/     ULONG32      CountCharsX;
/*0x09C*/     ULONG32      CountCharsY;
/*0x0A0*/     ULONG32      FillAttribute;
/*0x0A4*/     ULONG32      WindowFlags;
/*0x0A8*/     ULONG32      ShowWindowFlags;
/*0x0AC*/     UINT8        _PADDING1_[0x4];
/*0x0B0*/     struct _UNICODE_STRING WindowTitle;                    // 3 elements, 0x10 bytes (sizeof)
/*0x0C0*/     struct _UNICODE_STRING DesktopInfo;                    // 3 elements, 0x10 bytes (sizeof)
/*0x0D0*/     struct _UNICODE_STRING ShellInfo;                      // 3 elements, 0x10 bytes (sizeof)
/*0x0E0*/     struct _UNICODE_STRING RuntimeData;                    // 3 elements, 0x10 bytes (sizeof)
/*0x0F0*/     struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
/*0x3F0*/     UINT64       EnvironmentSize;
/*0x3F8*/     UINT64       EnvironmentVersion;
          } RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

typedef struct _PEB64 {                                    // 91 elements, 0x380 bytes (sizeof)
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union {                                                // 2 elements, 0x1 bytes (sizeof)
		/*0x003*/         UINT8        BitField;
		struct {                                           // 6 elements, 0x1 bytes (sizeof)
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition
			/*0x003*/             UINT8        IsLegacyProcess : 1;              // 2 BitPosition
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 3 BitPosition
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 4 BitPosition
			/*0x003*/             UINT8        SpareBits : 3;                    // 5 BitPosition
		};
	};
	/*0x008*/     UINT64       Mutant;
	/*0x010*/     UINT64       ImageBaseAddress;
	/*0x018*/     UINT64       Ldr;
	/*0x020*/     UINT64       ProcessParameters;
	/*0x028*/     UINT64       SubSystemData;
	/*0x030*/     UINT64       ProcessHeap;
	/*0x038*/     UINT64       FastPebLock;
	/*0x040*/     UINT64       AtlThunkSListPtr;
	/*0x048*/     UINT64       IFEOKey;
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x050*/         ULONG32      CrossProcessFlags;
		struct {                                           // 6 elements, 0x4 bytes (sizeof)
			/*0x050*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition
			/*0x050*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition
			/*0x050*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition
			/*0x050*/             ULONG32      ReservedBits0 : 27;               // 5 BitPosition
		};
	};
	union {                                                // 2 elements, 0x8 bytes (sizeof)
		/*0x058*/         UINT64       KernelCallbackTable;
		/*0x058*/         UINT64       UserSharedInfoPtr;
	};
	/*0x060*/     ULONG32      SystemReserved[1];
	/*0x064*/     ULONG32      AtlThunkSListPtr32;
	/*0x068*/     UINT64       ApiSetMap;
	/*0x070*/     ULONG32      TlsExpansionCounter;
	/*0x074*/     UINT8        _PADDING0_[0x4];
	/*0x078*/     UINT64       TlsBitmap;
	/*0x080*/     ULONG32      TlsBitmapBits[2];
	/*0x088*/     UINT64       ReadOnlySharedMemoryBase;
	/*0x090*/     UINT64       HotpatchInformation;
	/*0x098*/     UINT64       ReadOnlyStaticServerData;
	/*0x0A0*/     UINT64       AnsiCodePageData;
	/*0x0A8*/     UINT64       OemCodePageData;
	/*0x0B0*/     UINT64       UnicodeCaseTableData;
	/*0x0B8*/     ULONG32      NumberOfProcessors;
	/*0x0BC*/     ULONG32      NtGlobalFlag;
	/*0x0C0*/     union _LARGE_INTEGER CriticalSectionTimeout;           // 4 elements, 0x8 bytes (sizeof)
	/*0x0C8*/     UINT64       HeapSegmentReserve;
	/*0x0D0*/     UINT64       HeapSegmentCommit;
	/*0x0D8*/     UINT64       HeapDeCommitTotalFreeThreshold;
	/*0x0E0*/     UINT64       HeapDeCommitFreeBlockThreshold;
	/*0x0E8*/     ULONG32      NumberOfHeaps;
	/*0x0EC*/     ULONG32      MaximumNumberOfHeaps;
	/*0x0F0*/     UINT64       ProcessHeaps;
	/*0x0F8*/     UINT64       GdiSharedHandleTable;
	/*0x100*/     UINT64       ProcessStarterHelper;
	/*0x108*/     ULONG32      GdiDCAttributeList;
	/*0x10C*/     UINT8        _PADDING1_[0x4];
	/*0x110*/     UINT64       LoaderLock;
	/*0x118*/     ULONG32      OSMajorVersion;
	/*0x11C*/     ULONG32      OSMinorVersion;
	/*0x120*/     UINT16       OSBuildNumber;
	/*0x122*/     UINT16       OSCSDVersion;
	/*0x124*/     ULONG32      OSPlatformId;
	/*0x128*/     ULONG32      ImageSubsystem;
	/*0x12C*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x130*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x134*/     UINT8        _PADDING2_[0x4];
	/*0x138*/     UINT64       ActiveProcessAffinityMask;
	/*0x140*/     ULONG32      GdiHandleBuffer[60];
	/*0x230*/     UINT64       PostProcessInitRoutine;
	/*0x238*/     UINT64       TlsExpansionBitmap;
	/*0x240*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x2C0*/     ULONG32      SessionId;
	/*0x2C4*/     UINT8        _PADDING3_[0x4];
	/*0x2C8*/     union _ULARGE_INTEGER AppCompatFlags;                  // 4 elements, 0x8 bytes (sizeof)
	/*0x2D0*/     union _ULARGE_INTEGER AppCompatFlagsUser;              // 4 elements, 0x8 bytes (sizeof)
	/*0x2D8*/     UINT64       pShimData;
	/*0x2E0*/     UINT64       AppCompatInfo;
	/*0x2E8*/     struct _STRING CSDVersion;                           // 3 elements, 0x10 bytes (sizeof)
	/*0x2F8*/     UINT64       ActivationContextData;
	/*0x300*/     UINT64       ProcessAssemblyStorageMap;
	/*0x308*/     UINT64       SystemDefaultActivationContextData;
	/*0x310*/     UINT64       SystemAssemblyStorageMap;
	/*0x318*/     UINT64       MinimumStackCommit;
	/*0x320*/     UINT64       FlsCallback;
	/*0x328*/     struct _LIST_ENTRY FlsListHead;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x338*/     UINT64       FlsBitmap;
	/*0x340*/     ULONG32      FlsBitmapBits[4];
	/*0x350*/     ULONG32      FlsHighIndex;
	/*0x354*/     UINT8        _PADDING4_[0x4];
	/*0x358*/     UINT64       WerRegistrationData;
	/*0x360*/     UINT64       WerShipAssertPtr;
	/*0x368*/     UINT64       pContextData;
	/*0x370*/     UINT64       pImageHeaderHash;
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x378*/         ULONG32      TracingFlags;
		struct {                                           // 3 elements, 0x4 bytes (sizeof)
			/*0x378*/             ULONG32      HeapTracingEnabled : 1;           // 0 BitPosition
			/*0x378*/             ULONG32      CritSecTracingEnabled : 1;        // 1 BitPosition
			/*0x378*/             ULONG32      SpareTracingBits : 30;            // 2 BitPosition
		};
	};
} PEB64, *PPEB64;
#else
          typedef struct _LDR_DATA_TABLE_ENTRY32 {                       // 24 elements, 0x78 bytes (sizeof)
/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x8 bytes (sizeof)
/*0x008*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x8 bytes (sizeof)
/*0x010*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x8 bytes (sizeof)
/*0x018*/     VOID*        DllBase;
/*0x01C*/     VOID*        EntryPoint;
/*0x020*/     ULONG32      SizeOfImage;
/*0x024*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x8 bytes (sizeof)
/*0x02C*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x8 bytes (sizeof)
/*0x034*/     ULONG32      Flags;
/*0x038*/     UINT16       LoadCount;
/*0x03A*/     UINT16       TlsIndex;
              union {                                                  // 2 elements, 0x8 bytes (sizeof)
/*0x03C*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x8 bytes (sizeof)
                  struct {                                             // 2 elements, 0x8 bytes (sizeof)
/*0x03C*/             VOID*        SectionPointer;
/*0x040*/             ULONG32      CheckSum;
                  };
              };
              union {                                                  // 2 elements, 0x4 bytes (sizeof)
/*0x044*/         ULONG32      TimeDateStamp;
/*0x044*/         VOID*        LoadedImports;
              };
/*0x048*/     struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
/*0x04C*/     VOID*        PatchInformation;
/*0x050*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x8 bytes (sizeof)
/*0x058*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x8 bytes (sizeof)
/*0x060*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x8 bytes (sizeof)
/*0x068*/     VOID*        ContextInformation;
/*0x06C*/     ULONG32      OriginalBase;
/*0x070*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
          } LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

          typedef struct _PEB_LDR_DATA32 {                          // 9 elements, 0x30 bytes (sizeof)
/*0x000*/     ULONG32      Length;
/*0x004*/     UINT8        Initialized;
/*0x005*/     UINT8        _PADDING0_[0x3];
/*0x008*/     VOID*        SsHandle;
/*0x00C*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x8 bytes (sizeof)
/*0x014*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x8 bytes (sizeof)
/*0x01C*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x8 bytes (sizeof)
/*0x024*/     VOID*        EntryInProgress;
/*0x028*/     UINT8        ShutdownInProgress;
/*0x029*/     UINT8        _PADDING1_[0x3];
/*0x02C*/     VOID*        ShutdownThreadId;
          } PEB_LDR_DATA32, *PPEB_LDR_DATA32;

          typedef struct _RTL_USER_PROCESS_PARAMETERS32 {              // 30 elements, 0x298 bytes (sizeof)
/*0x000*/     ULONG32      MaximumLength;
/*0x004*/     ULONG32      Length;
/*0x008*/     ULONG32      Flags;
/*0x00C*/     ULONG32      DebugFlags;
/*0x010*/     VOID*        ConsoleHandle;
/*0x014*/     ULONG32      ConsoleFlags;
/*0x018*/     VOID*        StandardInput;
/*0x01C*/     VOID*        StandardOutput;
/*0x020*/     VOID*        StandardError;
/*0x024*/     struct _CURDIR CurrentDirectory;                       // 2 elements, 0xC bytes (sizeof)
/*0x030*/     struct _UNICODE_STRING DllPath;                        // 3 elements, 0x8 bytes (sizeof)
/*0x038*/     struct _UNICODE_STRING ImagePathName;                  // 3 elements, 0x8 bytes (sizeof)
/*0x040*/     struct _UNICODE_STRING CommandLine;                    // 3 elements, 0x8 bytes (sizeof)
/*0x048*/     VOID*        Environment;
/*0x04C*/     ULONG32      StartingX;
/*0x050*/     ULONG32      StartingY;
/*0x054*/     ULONG32      CountX;
/*0x058*/     ULONG32      CountY;
/*0x05C*/     ULONG32      CountCharsX;
/*0x060*/     ULONG32      CountCharsY;
/*0x064*/     ULONG32      FillAttribute;
/*0x068*/     ULONG32      WindowFlags;
/*0x06C*/     ULONG32      ShowWindowFlags;
/*0x070*/     struct _UNICODE_STRING WindowTitle;                    // 3 elements, 0x8 bytes (sizeof)
/*0x078*/     struct _UNICODE_STRING DesktopInfo;                    // 3 elements, 0x8 bytes (sizeof)
/*0x080*/     struct _UNICODE_STRING ShellInfo;                      // 3 elements, 0x8 bytes (sizeof)
/*0x088*/     struct _UNICODE_STRING RuntimeData;                    // 3 elements, 0x8 bytes (sizeof)
/*0x090*/     struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
/*0x290*/     ULONG32      EnvironmentSize;
/*0x294*/     ULONG32      EnvironmentVersion;
          } RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32 {                                    // 91 elements, 0x248 bytes (sizeof)
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union {                                                // 2 elements, 0x1 bytes (sizeof)
		/*0x003*/         UINT8        BitField;
		struct {                                           // 6 elements, 0x1 bytes (sizeof)
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition
			/*0x003*/             UINT8        IsLegacyProcess : 1;              // 2 BitPosition
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 3 BitPosition
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 4 BitPosition
			/*0x003*/             UINT8        SpareBits : 3;                    // 5 BitPosition
		};
	};
	/*0x004*/     ULONG32      Mutant;
	/*0x008*/     ULONG32      ImageBaseAddress;
	/*0x00C*/     ULONG32      Ldr;
	/*0x010*/     ULONG32      ProcessParameters;
	/*0x014*/     ULONG32      SubSystemData;
	/*0x018*/     ULONG32      ProcessHeap;
	/*0x01C*/     ULONG32      FastPebLock;
	/*0x020*/     ULONG32      AtlThunkSListPtr;
	/*0x024*/     ULONG32      IFEOKey;
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x028*/         ULONG32      CrossProcessFlags;
		struct {                                           // 6 elements, 0x4 bytes (sizeof)
			/*0x028*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition
			/*0x028*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition
			/*0x028*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition
			/*0x028*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition
			/*0x028*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition
			/*0x028*/             ULONG32      ReservedBits0 : 27;               // 5 BitPosition
		};
	};
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x02C*/         ULONG32      KernelCallbackTable;
		/*0x02C*/         ULONG32      UserSharedInfoPtr;
	};
	/*0x030*/     ULONG32      SystemReserved[1];
	/*0x034*/     ULONG32      AtlThunkSListPtr32;
	/*0x038*/     ULONG32      ApiSetMap;
	/*0x03C*/     ULONG32      TlsExpansionCounter;
	/*0x040*/     ULONG32      TlsBitmap;
	/*0x044*/     ULONG32      TlsBitmapBits[2];
	/*0x04C*/     ULONG32      ReadOnlySharedMemoryBase;
	/*0x050*/     ULONG32      HotpatchInformation;
	/*0x054*/     ULONG32      ReadOnlyStaticServerData;
	/*0x058*/     ULONG32      AnsiCodePageData;
	/*0x05C*/     ULONG32      OemCodePageData;
	/*0x060*/     ULONG32      UnicodeCaseTableData;
	/*0x064*/     ULONG32      NumberOfProcessors;
	/*0x068*/     ULONG32      NtGlobalFlag;
	/*0x06C*/     UINT8        _PADDING0_[0x4];
	/*0x070*/     union _LARGE_INTEGER CriticalSectionTimeout;           // 4 elements, 0x8 bytes (sizeof)
	/*0x078*/     ULONG32      HeapSegmentReserve;
	/*0x07C*/     ULONG32      HeapSegmentCommit;
	/*0x080*/     ULONG32      HeapDeCommitTotalFreeThreshold;
	/*0x084*/     ULONG32      HeapDeCommitFreeBlockThreshold;
	/*0x088*/     ULONG32      NumberOfHeaps;
	/*0x08C*/     ULONG32      MaximumNumberOfHeaps;
	/*0x090*/     ULONG32      ProcessHeaps;
	/*0x094*/     ULONG32      GdiSharedHandleTable;
	/*0x098*/     ULONG32      ProcessStarterHelper;
	/*0x09C*/     ULONG32      GdiDCAttributeList;
	/*0x0A0*/     ULONG32      LoaderLock;
	/*0x0A4*/     ULONG32      OSMajorVersion;
	/*0x0A8*/     ULONG32      OSMinorVersion;
	/*0x0AC*/     UINT16       OSBuildNumber;
	/*0x0AE*/     UINT16       OSCSDVersion;
	/*0x0B0*/     ULONG32      OSPlatformId;
	/*0x0B4*/     ULONG32      ImageSubsystem;
	/*0x0B8*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x0BC*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x0C0*/     ULONG32      ActiveProcessAffinityMask;
	/*0x0C4*/     ULONG32      GdiHandleBuffer[34];
	/*0x14C*/     ULONG32      PostProcessInitRoutine;
	/*0x150*/     ULONG32      TlsExpansionBitmap;
	/*0x154*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x1D4*/     ULONG32      SessionId;
	/*0x1D8*/     union _ULARGE_INTEGER AppCompatFlags;                  // 4 elements, 0x8 bytes (sizeof)
	/*0x1E0*/     union _ULARGE_INTEGER AppCompatFlagsUser;              // 4 elements, 0x8 bytes (sizeof)
	/*0x1E8*/     ULONG32      pShimData;
	/*0x1EC*/     ULONG32      AppCompatInfo;
	/*0x1F0*/     struct _STRING CSDVersion;                           // 3 elements, 0x8 bytes (sizeof)
	/*0x1F8*/     ULONG32      ActivationContextData;
	/*0x1FC*/     ULONG32      ProcessAssemblyStorageMap;
	/*0x200*/     ULONG32      SystemDefaultActivationContextData;
	/*0x204*/     ULONG32      SystemAssemblyStorageMap;
	/*0x208*/     ULONG32      MinimumStackCommit;
	/*0x20C*/     ULONG32      FlsCallback;
	/*0x210*/     struct _LIST_ENTRY FlsListHead;                      // 2 elements, 0x8 bytes (sizeof)
	/*0x218*/     ULONG32      FlsBitmap;
	/*0x21C*/     ULONG32      FlsBitmapBits[4];
	/*0x22C*/     ULONG32      FlsHighIndex;
	/*0x230*/     ULONG32      WerRegistrationData;
	/*0x234*/     ULONG32      WerShipAssertPtr;
	/*0x238*/     ULONG32      pContextData;
	/*0x23C*/     ULONG32      pImageHeaderHash;
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x240*/         ULONG32      TracingFlags;
		struct {                                           // 3 elements, 0x4 bytes (sizeof)
			/*0x240*/             ULONG32      HeapTracingEnabled : 1;           // 0 BitPosition
			/*0x240*/             ULONG32      CritSecTracingEnabled : 1;        // 1 BitPosition
			/*0x240*/             ULONG32      SpareTracingBits : 30;            // 2 BitPosition
		};
	};
} PEB32, *PPEB32;
#endif





/* End from winternl.h */

/* Begin from ddk.h */



#define PROCESSOR_FEATURE_MAX 64
#define MAX_WOW64_SHARED_ENTRIES 16

typedef enum _NT_PRODUCT_TYPE {
  NtProductWinNt = 1,
  NtProductLanManNt,
  NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef struct _KSYSTEM_TIME {
  ULONG LowPart;
  LONG High1Time;
  LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
  StandardDesign,
  NEC98x86,
  EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
  ULONG TickCountLowDeprecated;
  ULONG TickCountMultiplier;
  volatile KSYSTEM_TIME InterruptTime;
  volatile KSYSTEM_TIME SystemTime;
  volatile KSYSTEM_TIME TimeZoneBias;
  USHORT ImageNumberLow;
  USHORT ImageNumberHigh;
  WCHAR NtSystemRoot[260];
  ULONG MaxStackTraceDepth;
  ULONG CryptoExponent;
  ULONG TimeZoneId;
  ULONG LargePageMinimum;
  ULONG AitSamplingValue;
  ULONG AppCompatFlag;
  ULONGLONG RNGSeedVersion;
  ULONG GlobalValidationRunlevel;
  LONG TimeZoneBiasStamp;
  ULONG NtBuildNumber;
  NT_PRODUCT_TYPE NtProductType;
  BOOLEAN ProductTypeIsValid;
  ULONG NtMajorVersion;
  ULONG NtMinorVersion;
  BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
  ULONG Reserved1;
  ULONG Reserved3;
  volatile ULONG TimeSlip;
  ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
  ULONG AltArchitecturePad[1];
  LARGE_INTEGER SystemExpirationDate;
  ULONG SuiteMask;
  BOOLEAN KdDebuggerEnabled;
#if (NTDDI_VERSION >= NTDDI_WINXPSP2)
  UCHAR NXSupportPolicy;
#endif
  volatile ULONG ActiveConsoleId;
  volatile ULONG DismountCount;
  ULONG ComPlusPackage;
  ULONG LastSystemRITEventTickCount;
  ULONG NumberOfPhysicalPages;
  BOOLEAN SafeBootMode;
#if (NTDDI_VERSION >= NTDDI_WIN7)
  _ANONYMOUS_UNION union {
    UCHAR TscQpcData;
    _ANONYMOUS_STRUCT struct {
      UCHAR TscQpcEnabled:1;
      UCHAR TscQpcSpareFlag:1;
      UCHAR TscQpcShift:6;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
  UCHAR TscQpcPad[2];
#endif
#if (NTDDI_VERSION >= NTDDI_VISTA)
  _ANONYMOUS_UNION union {
    ULONG SharedDataFlags;
    _ANONYMOUS_STRUCT struct {
      ULONG DbgErrorPortPresent:1;
      ULONG DbgElevationEnabled:1;
      ULONG DbgVirtEnabled:1;
      ULONG DbgInstallerDetectEnabled:1;
      ULONG DbgSystemDllRelocated:1;
      ULONG DbgDynProcessorEnabled:1;
      ULONG DbgSEHValidationEnabled:1;
      ULONG SpareBits:25;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME2;
#else
  ULONG TraceLogging;
#endif
  ULONG DataFlagsPad[1];
  ULONGLONG TestRetInstruction;
  ULONG SystemCall;
  ULONG SystemCallReturn;
  ULONGLONG SystemCallPad[3];
  _ANONYMOUS_UNION union {
    volatile KSYSTEM_TIME TickCount;
    volatile ULONG64 TickCountQuad;
    _ANONYMOUS_STRUCT struct {
      ULONG ReservedTickCountOverlay[3];
      ULONG TickCountPad[1];
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME3;
  ULONG Cookie;
  ULONG CookiePad[1];
#if (NTDDI_VERSION >= NTDDI_WS03)
  LONGLONG ConsoleSessionForegroundProcessId;
  ULONG Wow64SharedInformation[MAX_WOW64_SHARED_ENTRIES];
#endif
#if (NTDDI_VERSION >= NTDDI_VISTA)
#if (NTDDI_VERSION >= NTDDI_WIN7)
  USHORT UserModeGlobalLogger[16];
#else
  USHORT UserModeGlobalLogger[8];
  ULONG HeapTracingPid[2];
  ULONG CritSecTracingPid[2];
#endif
  ULONG ImageFileExecutionOptions;
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
  ULONG LangGenerationCount;
#else
  /* 4 bytes padding */
#endif
  ULONGLONG Reserved5;
  volatile ULONG64 InterruptTimeBias;
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
  volatile ULONG64 TscQpcBias;
  volatile ULONG ActiveProcessorCount;
  volatile USHORT ActiveGroupCount;
  USHORT Reserved4;
  volatile ULONG AitSamplingValue;
  volatile ULONG AppCompatFlag;
  ULONGLONG SystemDllNativeRelocation;
  ULONG SystemDllWowRelocation;
  ULONG XStatePad[1];
  XSTATE_CONFIGURATION XState;
#endif
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;



/* End from ddk.h */

#if _WIN64 || _Win64
#define PEB PEB64
#define PPEB PPEB64
#define RTL_USER_PROCESS_PARAMETERS RTL_USER_PROCESS_PARAMETERS64
#define PRTL_USER_PROCESS_PARAMETERS PRTL_USER_PROCESS_PARAMETERS64
#define PEB_LDR_DATA PEB_LDR_DATA64
#define PPEB_LDR_DATA PPEB_LDR_DATA64
#define LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY64
#define PLDR_DATA_TABLE_ENTRY PLDR_DATA_TABLE_ENTRY64
#else
#define PEB PEB32
#define PPEB PPEB32
#define RTL_USER_PROCESS_PARAMETERS RTL_USER_PROCESS_PARAMETERS32
#define PRTL_USER_PROCESS_PARAMETERS PRTL_USER_PROCESS_PARAMETERS32
#define PEB_LDR_DATA PEB_LDR_DATA32
#define PPEB_LDR_DATA PPEB_LDR_DATA32
#define LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY32
#define PLDR_DATA_TABLE_ENTRY PLDR_DATA_TABLE_ENTRY32
#endif
