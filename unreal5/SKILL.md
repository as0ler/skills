---
name: unreal5
description: "Unreal Engine 5 internal structures and memory layouts for reverse engineering. Covers UObject hierarchy, FNamePool, FUObjectArray, FProperty system, UFunction, FField, GWorld, Large World Coordinates, and key UE5 global arrays. Use this when analyzing UE5 game binaries."
---

# Unreal Engine 5 Structures

Comprehensive reference for UE5 internal data structures used during reverse engineering. All offsets are for **64-bit builds** and should be verified per game build — custom engine modifications and compiler padding may shift fields.

> **Scope:** UE5.x only (5.0–5.5+). UE4 uses different structures (e.g., `TNameEntryArray` instead of `FNamePool`, `UProperty` instead of `FProperty`).

---

## 1. Core Object System

### 1.1 UObjectBase

The true root of the hierarchy. `UObject` inherits from `UObjectBase`.

```c
struct UObjectBase {
    void **VTableObject;         // 0x00 — virtual function table pointer
    EObjectFlags ObjectFlags;    // 0x08 — object flags (RF_Public, RF_Transactional, etc.)
    int32_t InternalIndex;       // 0x0C — index in GUObjectArray (FUObjectArray)
    UClass *ClassPrivate;        // 0x10 — pointer to this object's UClass (reflection metadata)
    FName NamePrivate;           // 0x18 — object name as FName (8 bytes: ComparisonIndex + Number)
    UObject *OuterPrivate;       // 0x20 — outer/owner object (package, level, etc.)
};
// sizeof(UObjectBase) = 0x28
```

**Key notes:**
- `ClassPrivate` at 0x10 is the most important field for RE — it gives access to all reflection data
- `NamePrivate` at 0x18 can be resolved to a string via FNamePool
- `InternalIndex` at 0x0C is the object's slot in GUObjectArray

### 1.2 UObject

```c
struct UObject : UObjectBase {
    // UObject adds no new data fields in UE5 — it adds virtual functions only
    // sizeof(UObject) = 0x28 (same as UObjectBase)
};
```

### 1.3 EObjectFlags (bitmask)

```c
enum EObjectFlags : uint32_t {
    RF_NoFlags                  = 0x00000000,
    RF_Public                   = 0x00000001,
    RF_Standalone               = 0x00000002,
    RF_MarkAsNative             = 0x00000004,
    RF_Transactional            = 0x00000008,
    RF_ClassDefaultObject       = 0x00000010,  // This is a CDO
    RF_ArchetypeObject          = 0x00000020,
    RF_Transient                = 0x00000040,
    RF_MarkAsRootSet            = 0x00000080,
    RF_TagGarbageTemp           = 0x00000100,
    RF_NeedInitialization       = 0x00000200,
    RF_NeedLoad                 = 0x00000400,
    RF_KeepForCooker            = 0x00000800,
    RF_NeedPostLoad             = 0x00001000,
    RF_NeedPostLoadSubobjects   = 0x00002000,
    RF_NewerVersionExists       = 0x00004000,
    RF_BeginDestroyed           = 0x00008000,
    RF_FinishDestroyed          = 0x00010000,
    RF_BeingRegenerated         = 0x00020000,
    RF_DefaultSubObject         = 0x00040000,
    RF_WasLoaded                = 0x00080000,
    RF_TextExportTransient      = 0x00100000,
    RF_LoadCompleted            = 0x00200000,
    RF_InheritableComponentTemplate = 0x00400000,
    RF_DuplicateTransient       = 0x00800000,
    RF_StrongRefOnFrame         = 0x01000000,
    RF_NonPIEDuplicateTransient = 0x02000000,
    RF_WillBeLoaded             = 0x20000000,
    RF_HasExternalPackage       = 0x40000000,
};
```

---

## 2. Name System (FNamePool)

UE5 replaced UE4's `TNameEntryArray` with a bucket-based `FNamePool`.

### 2.1 FName

```c
struct FName {
    FNameEntryId ComparisonIndex;  // 0x00 — index into FNamePool
    int32_t Number;                // 0x04 — instance number (0 = no suffix, >0 = "_N-1")
};
// sizeof(FName) = 0x08
```

**Usage:** `Number == 0` means the base name. `Number == 3` means the name has suffix `_2` (Number - 1).

### 2.2 FNameEntryId

```c
struct FNameEntryId {
    uint32_t Value;
    // Encodes:  Block index (upper bits) + Offset within block (lower bits)
    // Block  = Value >> FNameBlockOffsetBits
    // Offset = Value & ((1 << FNameBlockOffsetBits) - 1)
    // Typically FNameBlockOffsetBits = 16
};
```

**Decoding:**
```
block  = FNameEntryId.Value >> 16
offset = FNameEntryId.Value & 0xFFFF
```

### 2.3 FNamePool

```c
struct FNamePool {
    FRWLock Lock;                              // 0x00 — reader-writer lock (8 bytes)
    uint32_t CurrentBlock;                     // 0x08 — current active block index
    uint32_t CurrentByteCursor;                // 0x0C — write cursor within current block
    FNameEntryAllocator_Block Blocks[8192];    // 0x10 — array of block pointers
    // Each Blocks[i] is a pointer to a contiguous allocation
};
```

### 2.4 FNameEntry

```c
struct FNameEntry {
    uint16_t Header;
    // Header layout:
    //   Bit 0:     bIsWide (0 = ANSI/UTF-8, 1 = UTF-16)
    //   Bits 1-5:  ProbeHashBits (for case-insensitive lookup)  [UE 5.1+: Len stored differently]
    //   Bits 6-15: Len (string length, max 1024)
    //
    // Followed immediately by string data (no null terminator):
    //   if bIsWide:  char16_t Data[Len]
    //   else:        char     Data[Len]  (ANSI, not full UTF-8)
};
```

**Reading an FNameEntry:**
```
len     = Header >> 6
isWide  = Header & 1
strData = &entry + 2  (immediately after the 2-byte header)
```

**Stride:** Entries in FNamePool are aligned to 2-byte boundaries. The stride for addressing within a block is 2 bytes per unit (i.e., `offset * 2` gives the byte offset within the block).

### 2.5 FName Resolution Procedure

```
1. Extract ComparisonIndex.Value from FName
2. block  = Value >> 16
3. offset = Value & 0xFFFF
4. blockBase = FNamePool.Blocks[block]  (read pointer)
5. entryAddr = blockBase + (offset * 2)
6. header = read uint16 at entryAddr
7. len = header >> 6
8. isWide = header & 1
9. strData = entryAddr + 2
10. Read len bytes (ANSI) or len * 2 bytes (wide) from strData
```

> **Encryption warning:** Some UE5 titles XOR/rotate FNameEntry headers or string data. If step 7 yields garbage lengths, reverse the `FName::ToString` or `FName::AppendString` function to find the decryption logic — typically a compile-time XOR constant.

---

## 3. Object Array (FUObjectArray / GObjects)

### 3.1 FUObjectArray

```c
struct FUObjectArray {
    int32_t ObjFirstGCIndex;                       // 0x00
    int32_t ObjLastNonGCIndex;                      // 0x04
    int32_t MaxObjectsNotConsideredByGC;            // 0x08
    bool OpenForDisregardForGC;                     // 0x0C
    FChunkedFixedUObjectArray ObjObjects;            // 0x10 — the actual object storage
};
```

### 3.2 FChunkedFixedUObjectArray

```c
struct FChunkedFixedUObjectArray {
    FUObjectItem **Objects;      // 0x00 — array of chunk pointers
    FUObjectItem *PreAllocated;  // 0x08 — pre-allocated chunk (may be null)
    int32_t MaxElements;         // 0x10
    int32_t NumElements;         // 0x14 — total live objects count
    int32_t MaxChunks;           // 0x18
    int32_t NumChunks;           // 0x1C
};
// Elements per chunk = 65536 (0x10000)
```

### 3.3 FUObjectItem

```c
struct FUObjectItem {
    UObject *Object;             // 0x00 — pointer to the UObject (or null if slot is empty)
    int32_t Flags;               // 0x08 — internal GC flags
    int32_t ClusterRootIndex;    // 0x0C
    int32_t SerialNumber;        // 0x10
    // padding to 0x18
};
// sizeof(FUObjectItem) = 0x18
```

### 3.4 GObjects Traversal Procedure

```
1. Locate GUObjectArray global (exported or found via xrefs)
2. Read ObjObjects at offset 0x10 from GUObjectArray base
3. numElements = ObjObjects.NumElements (at ObjObjects + 0x14)
4. chunksBase = ObjObjects.Objects (at ObjObjects + 0x00, pointer to pointer array)
5. For index i = 0..numElements-1:
     chunkIndex  = i / 65536
     withinChunk = i % 65536
     chunkPtr    = read pointer at (chunksBase + chunkIndex * pointerSize)
     itemAddr    = chunkPtr + (withinChunk * 0x18)
     objPtr      = read pointer at itemAddr
     if objPtr != null:
       ClassPrivate = read pointer at (objPtr + 0x10)
       NamePrivate  = read FName at (objPtr + 0x18)
```

---

## 4. Reflection System

### 4.1 UField (legacy base)

```c
struct UField : UObject {
    UField *Next;            // 0x28 — next field in linked list (legacy, used for UFunctions)
};
// sizeof(UField) = 0x30
```

### 4.2 UStruct

```c
struct UStruct : UField {
    UStruct *SuperStruct;          // 0x30 — parent class/struct (inheritance chain)
    UField *Children;              // 0x38 — linked list of UField children (UFunctions only in UE5)
    FField *ChildProperties;       // 0x40 — UE5: FProperty chain (replaces UProperty for data fields)
    int32_t PropertiesSize;        // 0x48 — total byte size of instances of this struct
    int32_t MinAlignment;          // 0x4C — minimum required alignment
    TArray<uint8_t> Script;        // 0x50 — Blueprint bytecode (for BP classes)
    FProperty *PropertyLink;       // 0x68 — linked list for fast iteration over all properties
    FProperty *RefLink;            // 0x70 — reference property list (for GC)
    FProperty *DestructorLink;     // 0x78 — properties needing destruction
    FProperty *PostConstructLink;  // 0x80 — properties needing post-construct init
    TArray<UObject*> ScriptAndPropertyObjectReferences; // 0x88
    // ... additional fields
};
// sizeof(UStruct) varies — typically ~0xB0
```

**Important for RE:**
- `SuperStruct` at 0x30 lets you walk the inheritance chain
- `ChildProperties` at 0x40 is the FProperty linked list — **this is how you enumerate struct/class fields in UE5**
- `Children` at 0x38 still holds UFunctions
- `PropertiesSize` at 0x48 tells you the instance size

### 4.3 UClass

```c
struct UClass : UStruct {
    // Offsets below are approximate — verify per build
    UObject* (*ClassConstructor)(...);           // class constructor function pointer
    UObject* (*ClassVTableHelperCtorCaller)(...);
    FUObjectCppClassStaticFunctions ClassStaticFunctions;
    void (*ClassAddReferencedObjects)(UObject*, FReferenceCollector&);
    uint32_t ClassUnique;
    EClassFlags ClassFlags;                      // CLASS_Abstract, CLASS_Native, etc.
    EClassCastFlags ClassCastFlags;              // quick type-checking bitmask
    UClass *ClassWithin;                         // required outer class
    UObject *ClassGeneratedBy;                   // Blueprint that generated this class (or null)
    FName ClassConfigName;                       // config file name
    TArray<FRepRecord> ClassReps;                // net replication info
    TArray<UField*> NetFields;                   // network-relevant fields
    UObject *ClassDefaultObject;                 // CDO — the default template instance
    // ...
};
```

**Key fields for RE:**
- `ClassDefaultObject` (CDO) — read default property values from here
- `ClassFlags` — check for `CLASS_Abstract`, `CLASS_Native`, `CLASS_Config`
- `ClassCastFlags` — fast `IsA()` check for common types (AActor, APawn, UActorComponent, etc.)

### 4.4 EClassCastFlags (bitmask — commonly checked types)

```c
enum EClassCastFlags : uint64_t {
    CASTCLASS_None                  = 0x0000000000000000,
    CASTCLASS_UField                = 0x0000000000000001,
    CASTCLASS_FInt8Property         = 0x0000000000000002,
    CASTCLASS_UEnum                 = 0x0000000000000004,
    CASTCLASS_UStruct               = 0x0000000000000008,
    CASTCLASS_UScriptStruct         = 0x0000000000000010,
    CASTCLASS_UClass                = 0x0000000000000020,
    CASTCLASS_FByteProperty         = 0x0000000000000040,
    CASTCLASS_FIntProperty          = 0x0000000000000080,
    CASTCLASS_FFloatProperty        = 0x0000000000000100,
    CASTCLASS_FUInt64Property       = 0x0000000000000200,
    CASTCLASS_FClassProperty        = 0x0000000000000400,
    CASTCLASS_FUInt32Property       = 0x0000000000000800,
    CASTCLASS_FInterfaceProperty    = 0x0000000000001000,
    CASTCLASS_FNameProperty         = 0x0000000000002000,
    CASTCLASS_FStrProperty          = 0x0000000000004000,
    CASTCLASS_FProperty             = 0x0000000000008000,
    CASTCLASS_FObjectProperty       = 0x0000000000010000,
    CASTCLASS_FBoolProperty         = 0x0000000000020000,
    CASTCLASS_FUInt16Property       = 0x0000000000040000,
    CASTCLASS_UFunction             = 0x0000000000080000,
    CASTCLASS_FStructProperty       = 0x0000000000100000,
    CASTCLASS_FArrayProperty        = 0x0000000000200000,
    CASTCLASS_FInt64Property        = 0x0000000000400000,
    CASTCLASS_FDelegateProperty     = 0x0000000000800000,
    CASTCLASS_FNumericProperty      = 0x0000000001000000,
    CASTCLASS_FMulticastDelegateProperty = 0x0000000002000000,
    CASTCLASS_FObjectPropertyBase   = 0x0000000004000000,
    CASTCLASS_FWeakObjectProperty   = 0x0000000008000000,
    CASTCLASS_FLazyObjectProperty   = 0x0000000010000000,
    CASTCLASS_FSoftObjectProperty   = 0x0000000020000000,
    CASTCLASS_FTextProperty         = 0x0000000040000000,
    CASTCLASS_FInt16Property        = 0x0000000080000000,
    CASTCLASS_FDoubleProperty       = 0x0000000100000000,
    CASTCLASS_FSoftClassProperty    = 0x0000000200000000,
    CASTCLASS_UPackage              = 0x0000000400000000,
    CASTCLASS_ULevel                = 0x0000000800000000,
    CASTCLASS_AActor                = 0x0000001000000000,
    CASTCLASS_APlayerController     = 0x0000002000000000,
    CASTCLASS_APawn                 = 0x0000004000000000,
    CASTCLASS_USceneComponent       = 0x0000008000000000,
    CASTCLASS_UPrimitiveComponent   = 0x0000010000000000,
    CASTCLASS_USkinnedMeshComponent = 0x0000020000000000,
    CASTCLASS_USkeletalMeshComponent= 0x0000040000000000,
    CASTCLASS_UBlueprint            = 0x0000080000000000,
    CASTCLASS_UDelegateFunction     = 0x0000100000000000,
    CASTCLASS_UStaticMeshComponent  = 0x0000200000000000,
    CASTCLASS_FMapProperty          = 0x0000400000000000,
    CASTCLASS_FSetProperty          = 0x0000800000000000,
    CASTCLASS_FEnumProperty         = 0x0001000000000000,
    CASTCLASS_USparseDelegateFunction = 0x0002000000000000,
    CASTCLASS_FMulticastInlineDelegateProperty = 0x0004000000000000,
    CASTCLASS_FMulticastSparseDelegateProperty = 0x0008000000000000,
    CASTCLASS_FFieldPathProperty    = 0x0010000000000000,
    CASTCLASS_FObjectPtrProperty    = 0x0020000000000000,  // UE5: TObjectPtr
    CASTCLASS_FClassPtrProperty     = 0x0040000000000000,  // UE5: TClassPtr
    CASTCLASS_FLargeWorldCoordinatesRealProperty = 0x0080000000000000, // UE5 LWC
};
```

---

## 5. FField / FProperty System (UE5)

UE5 replaced `UProperty` (which was a full `UObject`) with lightweight `FField`/`FProperty` objects. These are **not** in GUObjectArray — they are allocated separately and linked from `UStruct::ChildProperties`.

### 5.1 FFieldClass

```c
struct FFieldClass {
    FName Name;                      // 0x00 — type name (e.g., "StructProperty", "FloatProperty")
    uint64_t Id;                     // 0x08 — unique type ID
    uint64_t CastFlags;             // 0x10 — CASTCLASS_* bitmask for fast type checks
    EClassFlags ClassFlags;          // 0x18
    FFieldClass *SuperClass;         // 0x20 — parent FFieldClass
    // ...
};
```

### 5.2 FField

```c
struct FField {
    void **VTableObject;             // 0x00 — vtable
    FFieldClass *ClassPrivate;       // 0x08 — type descriptor (FFieldClass)
    FFieldVariant Owner;             // 0x10 — union: owning UStruct* or FField*
                                     //         FFieldVariant = { void* Value; bool bIsUObject; }
                                     //         sizeof = 0x10 (pointer + bool + padding)
    FField *Next;                    // 0x20 — next in linked list
    FName NamePrivate;               // 0x28 — property name
    EObjectFlags FlagsPrivate;       // 0x30
};
// sizeof(FField) = 0x38
```

### 5.3 FProperty

```c
struct FProperty : FField {
    int32_t ArrayDim;                // 0x38 — static array dimension (usually 1)
    int32_t ElementSize;             // 0x3C — size of a single element
    EPropertyFlags PropertyFlags;    // 0x40 — CPF_* flags (uint64_t)
    uint16_t RepIndex;               // 0x48 — replication index
    uint16_t BlueprintReplicationCondition; // 0x4A
    int32_t Offset_Internal;         // 0x4C — byte offset of this property within the owning struct instance
    FName RepNotifyFunc;             // 0x50 — name of OnRep function (if replicated)
    FProperty *PropertyLinkNext;     // 0x58 — next in UStruct::PropertyLink chain
    FProperty *NextRef;              // 0x60 — next in UStruct::RefLink chain
    FProperty *DestructorLinkNext;   // 0x68
    FProperty *PostConstructLinkNext;// 0x70
    // ...
};
// sizeof(FProperty) = 0x78
```

**Key field for RE:** `Offset_Internal` at 0x4C — this is the byte offset where this property's data lives within an instance of the owning struct/class.

### 5.4 EPropertyFlags (bitmask)

```c
enum EPropertyFlags : uint64_t {
    CPF_None                    = 0,
    CPF_Edit                    = 0x0000000000000001,  // editable in editor
    CPF_ConstParm               = 0x0000000000000002,
    CPF_BlueprintVisible        = 0x0000000000000004,
    CPF_ExportObject            = 0x0000000000000008,
    CPF_BlueprintReadOnly       = 0x0000000000000010,
    CPF_Net                     = 0x0000000000000020,  // replicated
    CPF_EditFixedSize           = 0x0000000000000040,
    CPF_Parm                    = 0x0000000000000080,  // function parameter
    CPF_OutParm                 = 0x0000000000000100,  // output parameter
    CPF_ZeroConstructor         = 0x0000000000000200,
    CPF_ReturnParm              = 0x0000000000000400,  // return value
    CPF_DisableEditOnTemplate   = 0x0000000000000800,
    CPF_Transient               = 0x0000000000002000,
    CPF_Config                  = 0x0000000000004000,  // from .ini config
    CPF_DisableEditOnInstance   = 0x0000000000010000,
    CPF_EditConst               = 0x0000000000020000,
    CPF_GlobalConfig            = 0x0000000000040000,
    CPF_InstancedReference      = 0x0000000000080000,
    CPF_DuplicateTransient      = 0x0000000000200000,
    CPF_SaveGame                = 0x0000000001000000,  // saved in save games
    CPF_NoClear                 = 0x0000000002000000,
    CPF_ReferenceParm           = 0x0000000008000000,
    CPF_BlueprintAssignable     = 0x0000000010000000,
    CPF_Deprecated              = 0x0000000020000000,
    CPF_IsPlainOldData          = 0x0000000040000000,
    CPF_RepSkip                 = 0x0000000080000000,
    CPF_RepNotify               = 0x0000000100000000,  // has OnRep callback
    CPF_Interp                  = 0x0000000200000000,
    CPF_NonTransactional        = 0x0000000400000000,
    CPF_EditorOnly              = 0x0000000800000000,
    CPF_NoDestructor            = 0x0000001000000000,
    CPF_AutoWeak                = 0x0000004000000000,
    CPF_ContainsInstancedReference = 0x0000008000000000,
    CPF_AssetRegistrySearchable = 0x0000010000000000,
    CPF_SimpleDisplay           = 0x0000020000000000,
    CPF_AdvancedDisplay         = 0x0000040000000000,
    CPF_Protected               = 0x0000080000000000,
    CPF_BlueprintCallable       = 0x0000100000000000,
    CPF_BlueprintAuthorityOnly  = 0x0000200000000000,
    CPF_TextExportTransient     = 0x0000400000000000,
    CPF_NonPIEDuplicateTransient= 0x0000800000000000,
    CPF_ExposeOnSpawn           = 0x0001000000000000,
    CPF_PersistentInstance      = 0x0002000000000000,
    CPF_UObjectWrapper          = 0x0004000000000000,
    CPF_HasGetValueTypeHash     = 0x0008000000000000,
    CPF_NativeAccessSpecifierPublic    = 0x0010000000000000,
    CPF_NativeAccessSpecifierProtected = 0x0020000000000000,
    CPF_NativeAccessSpecifierPrivate   = 0x0040000000000000,
    CPF_SkipSerialization       = 0x0080000000000000,
};
```

### 5.5 Common FProperty Subtypes

| Subtype | FFieldClass Name | Data Description |
|---------|-----------------|------------------|
| `FBoolProperty` | `BoolProperty` | Single bit or byte boolean. Has `FieldSize`, `ByteOffset`, `ByteMask`, `FieldMask` for bitfield access. |
| `FByteProperty` | `ByteProperty` | `uint8_t`, optionally backed by a `UEnum`. |
| `FIntProperty` | `IntProperty` | `int32_t` |
| `FInt64Property` | `Int64Property` | `int64_t` |
| `FFloatProperty` | `FloatProperty` | `float` (32-bit) |
| `FDoubleProperty` | `DoubleProperty` | `double` (64-bit) — used extensively in UE5 LWC |
| `FStrProperty` | `StrProperty` | `FString` (heap-allocated `TArray<TCHAR>`) |
| `FNameProperty` | `NameProperty` | `FName` (8 bytes) |
| `FTextProperty` | `TextProperty` | `FText` (localized string, complex internal layout) |
| `FObjectProperty` | `ObjectProperty` | Raw `UObject*` pointer. Has `PropertyClass` field pointing to the expected UClass. |
| `FObjectPtrProperty` | `ObjectPtrProperty` | UE5 `TObjectPtr<T>` — lazy-resolved object reference. `FObjectPtr { FObjectHandle Handle; }` |
| `FWeakObjectProperty` | `WeakObjectProperty` | `TWeakObjectPtr<T>` — `{ int32_t ObjectIndex; int32_t ObjectSerialNumber; }` |
| `FSoftObjectProperty` | `SoftObjectProperty` | `TSoftObjectPtr<T>` — `{ FSoftObjectPath { FTopLevelAssetPath, FString SubPath } }` |
| `FStructProperty` | `StructProperty` | Inline struct. Has `Struct` field → `UScriptStruct*` for the struct type definition. |
| `FArrayProperty` | `ArrayProperty` | `TArray<T>`. Has `Inner` → `FProperty*` for element type. |
| `FMapProperty` | `MapProperty` | `TMap<K,V>`. Has `KeyProp` and `ValueProp` → `FProperty*`. |
| `FSetProperty` | `SetProperty` | `TSet<T>`. Has `ElementProp` → `FProperty*`. |
| `FEnumProperty` | `EnumProperty` | Backed by `UEnum*`. Has `UnderlyingProp` → `FNumericProperty*` for storage type. |
| `FDelegateProperty` | `DelegateProperty` | Singlecast delegate. Has `SignatureFunction` → `UFunction*`. |
| `FMulticastDelegateProperty` | `MulticastInlineDelegateProperty` | Multicast delegate (event dispatcher). |
| `FInterfaceProperty` | `InterfaceProperty` | `TScriptInterface<T>`. Has `InterfaceClass` → `UClass*`. |
| `FClassProperty` | `ClassProperty` | `TSubclassOf<T>`. Has `MetaClass` → `UClass*` for the base class constraint. |
| `FFieldPathProperty` | `FieldPathProperty` | `TFieldPath<T>` — path to an FField. |

---

## 6. UFunction

### 6.1 UFunction Layout

```c
struct UFunction : UStruct {
    // UStruct fields first (~0xB0), then:
    uint32_t FunctionFlags;          // FUNC_* bitmask
    uint8_t NumParms;                // total parameter count (including return value)
    uint16_t ParmsSize;              // total size of all parameters
    uint16_t ReturnValueOffset;      // byte offset of return value within params struct
    uint16_t RPCId;                  // network RPC identifier
    uint16_t RPCResponseId;          // expected response RPC ID
    FProperty *FirstPropertyToInit;  // first property needing initialization
    UFunction *EventGraphFunction;   // for BP: the event graph containing this function
    int32_t EventGraphCallOffset;
    void *Func;                      // native implementation pointer (for FUNC_Native functions)
    // Func == &UObject::ProcessInternal for Blueprint-only functions
};
```

### 6.2 EFunctionFlags

```c
enum EFunctionFlags : uint32_t {
    FUNC_None                   = 0x00000000,
    FUNC_Final                  = 0x00000001,  // cannot be overridden
    FUNC_RequiredAPI            = 0x00000002,
    FUNC_BlueprintAuthorityOnly = 0x00000004,
    FUNC_BlueprintCosmetic      = 0x00000008,
    FUNC_Net                    = 0x00000040,  // replicated function
    FUNC_NetReliable            = 0x00000080,
    FUNC_NetRequest             = 0x00000100,  // client → server RPC
    FUNC_Exec                   = 0x00000200,  // console command
    FUNC_Native                 = 0x00000400,  // C++ implementation (Func points to native code)
    FUNC_Event                  = 0x00000800,  // event (BlueprintImplementableEvent)
    FUNC_NetResponse            = 0x00001000,  // server → client response
    FUNC_Static                 = 0x00002000,
    FUNC_NetMulticast           = 0x00004000,  // multicast RPC
    FUNC_UbergraphFunction      = 0x00008000,  // auto-generated event graph function
    FUNC_MulticastDelegate      = 0x00010000,
    FUNC_Public                 = 0x00020000,
    FUNC_Private                = 0x00040000,
    FUNC_Protected              = 0x00080000,
    FUNC_Delegate               = 0x00100000,
    FUNC_NetServer              = 0x00200000,  // server-only RPC
    FUNC_NetClient              = 0x00400000,  // client-only RPC
    FUNC_DLLImport              = 0x00800000,
    FUNC_BlueprintCallable      = 0x04000000,
    FUNC_BlueprintEvent         = 0x08000000,
    FUNC_BlueprintPure          = 0x10000000,
    FUNC_EditorOnly             = 0x20000000,
    FUNC_Const                  = 0x40000000,
    FUNC_NetValidate            = 0x80000000,
    FUNC_AllFlags               = 0xFFFFFFFF,
};
```

### 6.3 UFunction Parameter Layout

UFunction parameters are stored as a contiguous struct. Each parameter is an FProperty in the function's `ChildProperties` chain:

```
1. Walk UFunction.ChildProperties (FProperty linked list)
2. For each FProperty:
   - Check PropertyFlags for CPF_Parm (is a parameter)
   - Check PropertyFlags for CPF_ReturnParm (is the return value)
   - Check PropertyFlags for CPF_OutParm (is an output parameter)
   - Offset_Internal gives the offset within the params struct
   - ElementSize gives the size
3. Total params struct size = UFunction.ParmsSize
```

---

## 7. World and Actor System

### 7.1 GWorld

```c
// GWorld is a global pointer:
UWorld **GWorld;  // dereference once to get the current UWorld*
```

### 7.2 UWorld (key fields)

```c
struct UWorld : UObject {
    // ... many fields, offsets vary significantly per build
    // Key fields to locate (use FProperty walk or pattern matching):
    ULevel *PersistentLevel;             // the always-loaded level
    FName StreamingLevelsPrefix;
    ULevel *CurrentLevelPendingVisibility;
    ULevel *CurrentLevelPendingInvisibility;
    UDemoNetDriver *DemoNetDriver;
    AGameStateBase *GameState;           // current game state
    TArray<ULevel*> Levels;              // all loaded levels
    TArray<AActor*> LevelActors;         // direct accessor varies
    AGameModeBase *AuthorityGameMode;    // server only
    UGameInstance *OwningGameInstance;
    // ...
};
```

### 7.3 ULevel

```c
struct ULevel : UObject {
    // ...
    TArray<AActor*> Actors;      // all actors in this level
    // The Actors TArray is typically the first or second TArray field
    // Find it by searching for a TArray whose elements are valid UObject* with AActor class
};
```

### 7.4 AActor (key fields)

```c
struct AActor : UObject {
    // After UObject fields (0x28), AActor adds:
    // ... many fields, verify offsets per build
    USceneComponent *RootComponent;      // root transform component
    TArray<UActorComponent*> OwnedComponents;  // all components
    AActor *Owner;                       // owning actor
    FName NetDriverName;
    ENetRole Role;                       // authority, simulated proxy, autonomous proxy
    ENetRole RemoteRole;
    FRepMovement ReplicatedMovement;
    // ...
};
```

### 7.5 TArray<T>

```c
template<typename T>
struct TArray {
    T *Data;                // 0x00 — pointer to heap-allocated array
    int32_t ArrayNum;       // 0x08 — current element count
    int32_t ArrayMax;       // 0x0C — allocated capacity
};
// sizeof(TArray) = 0x10
```

### 7.6 FString

```c
struct FString {
    TArray<TCHAR> Data;     // TArray<char16_t> on Windows, TArray<char> on Linux/Mac (UTF-8 in UE5)
};
// sizeof(FString) = 0x10
```

---

## 8. Large World Coordinates (LWC)

UE5 uses `double` precision for spatial data:

### 8.1 FVector (UE5 LWC)

```c
struct FVector {
    double X;   // 0x00
    double Y;   // 0x08
    double Z;   // 0x10
};
// sizeof(FVector) = 0x18 (24 bytes) — vs 0x0C (12 bytes) in UE4
```

### 8.2 FRotator

```c
struct FRotator {
    double Pitch;   // 0x00
    double Yaw;     // 0x08
    double Roll;    // 0x10
};
// sizeof(FRotator) = 0x18
```

### 8.3 FTransform

```c
struct FTransform {
    FQuat Rotation;      // 0x00 — { double X, Y, Z, W } = 32 bytes
    FVector Translation; // 0x20 — 24 bytes
    FVector Scale3D;     // 0x38 — 24 bytes
};
// sizeof(FTransform) = 0x50 (80 bytes, with potential padding to 0x60)
// Note: may be aligned to 16 or 32 bytes depending on SIMD configuration
```

### 8.4 Impact on RE

- All `FVector`, `FRotator`, `FTransform` reads must use `readDouble()` instead of `readFloat()`
- Property offsets and struct sizes are larger than UE4 equivalents
- Physics, navigation, AI, and gameplay code all use double precision
- `FLargeWorldCoordinatesRealProperty` in the reflection system marks LWC-aware properties

---

## 9. Commonly Needed Offset Summary

Quick reference table (verify per build — offsets can shift):

| Structure | Field | Typical Offset | Size |
|-----------|-------|---------------|------|
| `UObject` | `VTable` | 0x00 | 8 |
| `UObject` | `ObjectFlags` | 0x08 | 4 |
| `UObject` | `InternalIndex` | 0x0C | 4 |
| `UObject` | `ClassPrivate` | 0x10 | 8 |
| `UObject` | `NamePrivate` | 0x18 | 8 |
| `UObject` | `OuterPrivate` | 0x20 | 8 |
| `UField` | `Next` | 0x28 | 8 |
| `UStruct` | `SuperStruct` | 0x30 | 8 |
| `UStruct` | `Children` | 0x38 | 8 |
| `UStruct` | `ChildProperties` | 0x40 | 8 |
| `UStruct` | `PropertiesSize` | 0x48 | 4 |
| `FField` | `ClassPrivate` | 0x08 | 8 |
| `FField` | `Next` | 0x20 | 8 |
| `FField` | `NamePrivate` | 0x28 | 8 |
| `FProperty` | `ElementSize` | 0x3C | 4 |
| `FProperty` | `PropertyFlags` | 0x40 | 8 |
| `FProperty` | `Offset_Internal` | 0x4C | 4 |
| `FUObjectItem` | `Object` | 0x00 | 8 |
| `FUObjectItem` | (total size) | — | 0x18 |
| `FName` | `ComparisonIndex` | 0x00 | 4 |
| `FName` | `Number` | 0x04 | 4 |
| `TArray` | `Data` | 0x00 | 8 |
| `TArray` | `ArrayNum` | 0x08 | 4 |
| `TArray` | `ArrayMax` | 0x0C | 4 |
| `FVector` (LWC) | `X,Y,Z` | 0x00 | 3×8=24 |

> **Disclaimer:** These offsets are based on standard UE5 builds (5.1–5.4). Custom engine forks, plugin-heavy builds, or games with source-level modifications may have different layouts. Always verify with static analysis before relying on hardcoded offsets.
