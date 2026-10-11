param(
    [int]$ProcessId = 0,
    [string]$GameId = "GSAE01"
)

$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class LiveDolphinProbeNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation64 {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint Alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint Alignment2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UIntPtr VirtualQueryEx(
        IntPtr process,
        UIntPtr address,
        out MemoryBasicInformation64 info,
        UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr process,
        UIntPtr address,
        [Out] byte[] buffer,
        int size,
        out IntPtr bytesRead);
}
'@

if ($ProcessId -eq 0) {
    $process = Get-Process | Where-Object {
        $_.ProcessName -eq "Dolphin" -and $_.MainWindowTitle -like "*$GameId*"
    } | Select-Object -First 1
} else {
    $process = Get-Process -Id $ProcessId
}

if ($null -eq $process) {
    throw "No Dolphin process running $GameId was found."
}

function Read-HostBytes([uint64]$address, [int]$size) {
    $buffer = New-Object byte[] $size
    $bytesRead = [IntPtr]::Zero
    $ok = [LiveDolphinProbeNative]::ReadProcessMemory(
        $process.Handle,
        [UIntPtr]$address,
        $buffer,
        $size,
        [ref]$bytesRead)
    if (-not $ok -or $bytesRead.ToInt64() -ne $size) {
        throw ("ReadProcessMemory failed at host 0x{0:X} for 0x{1:X} bytes" -f $address, $size)
    }
    return $buffer
}

$mem1Base = $null
$queryAddress = [uint64]0
$infoSize = [uint64][Runtime.InteropServices.Marshal]::SizeOf(
    [type][LiveDolphinProbeNative+MemoryBasicInformation64])
while ($queryAddress -lt 0x00007FFFFFFFFFFF) {
    $info = New-Object LiveDolphinProbeNative+MemoryBasicInformation64
    $result = [LiveDolphinProbeNative]::VirtualQueryEx(
        $process.Handle,
        [UIntPtr]$queryAddress,
        [ref]$info,
        [UIntPtr]$infoSize)
    if ($result -eq [UIntPtr]::Zero) {
        break
    }
    if ($info.RegionSize -eq 0x02000000 -and $info.State -eq 0x1000) {
        try {
            $id = [Text.Encoding]::ASCII.GetString((Read-HostBytes $info.BaseAddress 6))
            if ($id -eq $GameId) {
                $mem1Base = $info.BaseAddress
                break
            }
        } catch {
        }
    }
    $nextAddress = $info.BaseAddress + $info.RegionSize
    if ($nextAddress -le $queryAddress) {
        break
    }
    $queryAddress = $nextAddress
}

if ($null -eq $mem1Base) {
    throw "Could not locate Dolphin's mapped MEM1 region."
}

function Convert-ToHostAddress([uint32]$address) {
    if ($address -lt 0x80000000L -or $address -ge 0x82000000L) {
        throw ("Address 0x{0:X8} is outside MEM1" -f $address)
    }
    return [uint64]$mem1Base + ([uint64]$address - 0x80000000L)
}

function Read-Bytes([uint32]$address, [int]$size) {
    return Read-HostBytes (Convert-ToHostAddress $address) $size
}

function Read-U8([uint32]$address) {
    return [uint32](Read-Bytes $address 1)[0]
}

function Read-BE16([uint32]$address) {
    $bytes = Read-Bytes $address 2
    return [uint32](([uint32]$bytes[0] -shl 8) -bor [uint32]$bytes[1])
}

function Read-BES16([uint32]$address) {
    $value = Read-BE16 $address
    if ($value -ge 0x8000) {
        return [int]$value - 0x10000
    }
    return [int]$value
}

function Read-BE32([uint32]$address) {
    $bytes = Read-Bytes $address 4
    return [uint32](([uint32]$bytes[0] -shl 24) -bor
        ([uint32]$bytes[1] -shl 16) -bor
        ([uint32]$bytes[2] -shl 8) -bor
        [uint32]$bytes[3])
}

function Read-BEFloat([uint32]$address) {
    $bits = Read-BE32 $address
    return [BitConverter]::ToSingle([BitConverter]::GetBytes($bits), 0)
}

function Read-AsciiZ([uint32]$address, [int]$maxLength) {
    $bytes = Read-Bytes $address $maxLength
    $length = 0
    while ($length -lt $bytes.Length -and $bytes[$length] -ne 0) {
        $length++
    }
    return [Text.Encoding]::ASCII.GetString($bytes, 0, $length)
}

function Test-Mem1Pointer([uint32]$address) {
    return $address -ge 0x80000000L -and $address -lt 0x82000000L
}

function Format-Pointer([uint32]$address) {
    return "0x{0:X8}" -f $address
}

$tagNames = @{
    0x00000000 = "ZERO"; 0x00000001 = "LISTS_COL"; 0x00000002 = "SCREEN_COL"
    0x00000003 = "CODE_COL"; 0x00000004 = "DLL_COL"; 0x00000005 = "TRACK_COL"
    0x00000006 = "TEX_COL"; 0x00000007 = "TRACKTEX_COL"; 0x00000008 = "SPRITETEX_COL"
    0x00000009 = "MODELS_COL"; 0x0000000A = "ANIMS_COL"; 0x0000000B = "AUDIO_COL"
    0x0000000C = "SEQ_COL"; 0x0000000D = "SFX_COL"; 0x0000000E = "OBJECTS_COL"
    0x0000000F = "CAM_COL"; 0x00000010 = "VOX_COL"; 0x00000011 = "ANIMSEQ_COL"
    0x00000012 = "LFX_COL"; 0x00000013 = "GFX_COL"; 0x00000014 = "EXPGFX_COL"
    0x00000015 = "MODGFX_COL"; 0x00000016 = "PROJGFX_COL"; 0x00000017 = "SKY_COL"
    0x00000018 = "SHAD_COL"; 0x00000019 = "GAME_COL"; 0x0000001A = "TEST_COL"
    0x0000EEFF = "OBJECTS"; 0x00880099 = "VOX"; 0x008888FF = "ANIMS"
    0x00EE00FF = "TRACK"; 0x00EEEEFF = "MODELS"; 0x12345678 = "GAME"
    0x4050FFFF = "ANIMSEQ"; 0x7D7D7D7D = "FILE"; 0x7E7E7EFE = "CODE"
    0x7F7F7F99 = "SHAD"; 0x7F7F7FFF = "COMPRESSED_FILE"; 0x88000099L = "CAM"
    0x8E8E8EFEL = "DLL"; 0xCECECEFEL = "LISTS"; 0xEE0000BBL = "SFX"
    0xEE0000DDL = "SEQ"; 0xEE0000FFL = "AUDIO"; 0xEE00EE99L = "SPRITETEX"
    0xEE00EECCL = "TRACKTEX"; 0xEE00EEFFL = "TEX"; 0xEEEEEEFEL = "SCREEN"
    0xFACEFEEDL = "FACEFEED"; 0xFF3300FFL = "SKY"; 0xFF5500FFL = "PROJGFX"
    0xFF7700FFL = "MODGFX"; 0xFF9900FFL = "EXPGFX"; 0xFFAA00FFL = "GFX"
    0xFFCC00FFL = "LFX"; 0xFFDD00FFL = "TEST"; 0xFFFF00FFL = "INTERSECT_POINT"
    0xFFFFFFFFL = "SAVEGAME"
}
$tagNamesByHex = @{}
foreach ($tagKey in $tagNames.Keys) {
    $tagNamesByHex[("{0:X8}" -f ([uint32]$tagKey))] = $tagNames[$tagKey]
}

"Dolphin PID: {0}" -f $process.Id
"MEM1 host base: 0x{0:X}" -f $mem1Base
"Game ID: {0}" -f ([Text.Encoding]::ASCII.GetString((Read-Bytes 0x80000000L 6)))
""
"Core counters"
$coreCounters = [ordered]@{
    ObjCount = Read-BE32 0x803DCB84L
    PendingDefFreeCount = Read-BE32 0x803DCB8CL
    DeferredFreeCount = Read-BE32 0x803DCB94L
    ObjectTypeListCount = Read-U8 0x803DCBF0L
    EffectBoxCount = Read-U8 0x803DCB74L
    LoadedTextureCount = Read-BE32 0x803DCDBCL
    ShaderRomListSlotCount = Read-U8 0x803DCDECL
    MapBlockCount = Read-U8 0x803DCE98L
}
$coreCounters.GetEnumerator() | ForEach-Object { "  {0,-25} {1}" -f $_.Key, $_.Value }

""
"Object-type boundaries"
$typeOffsets = Read-Bytes 0x80342CF8L 0x55
$groups = @(0x34, 0x3E, 0x41, 0x4D, 0x4E, 0x4F, 0x50)
foreach ($group in $groups) {
    $start = $typeOffsets[$group]
    $end = $typeOffsets[$group + 1]
    "  group {0:X2}: start={1,3} end={2,3} signedCount={3,4}" -f $group, $start, $end, ([int]$end - [int]$start)
}
"  final boundary [54]: {0}" -f $typeOffsets[0x54]

""
"Object registry scan (all 256 slots)"
$registryPointers = for ($index = 0; $index -lt 256; $index++) {
    Read-BE32 ([uint32](0x803428F8L + 4 * $index))
}
$validRegistry = @($registryPointers | Where-Object { Test-Mem1Pointer $_ })
$nonzeroRegistry = @($registryPointers | Where-Object { $_ -ne 0 })
"  nonzero={0} validMEM1={1} distinctValid={2}" -f $nonzeroRegistry.Count, $validRegistry.Count, @($validRegistry | Sort-Object -Unique).Count
$magicPlantRegistry = @()
for ($index = 0; $index -lt 256; $index++) {
    $object = $registryPointers[$index]
    if (-not (Test-Mem1Pointer $object)) {
        continue
    }
    try {
        $definition = Read-BE32 ([uint32]($object + 0x50))
        if (-not (Test-Mem1Pointer $definition)) {
            continue
        }
        $dllId = Read-BE16 ([uint32]($definition + 0x50))
        if ($dllId -eq 254) {
            $magicPlantRegistry += [pscustomobject]@{
                Slot = $index
                Object = Format-Pointer $object
                RomDefNo = Read-BE16 ([uint32]($object + 0x46))
                Flags = "0x{0:X4}" -f (Read-BE16 ([uint32]($object + 0xB0)))
            }
        }
    } catch {
    }
}
"  MagicPlant memberships found: {0}" -f $magicPlantRegistry.Count
$magicPlantRegistry | Format-Table -AutoSize | Out-String -Width 200

"Live object list"
$objCount = $coreCounters.ObjCount
$objList = Read-BE32 0x803DCB88L
"  ptr={0} count={1}" -f (Format-Pointer $objList), $objCount
$livePlants = @()
$liveObjectSet = @{}
if ((Test-Mem1Pointer $objList) -and $objCount -lt 2000) {
    for ($index = 0; $index -lt $objCount; $index++) {
        $object = Read-BE32 ([uint32]($objList + 4 * $index))
        if (-not (Test-Mem1Pointer $object)) {
            continue
        }
        $liveObjectSet[(Format-Pointer $object)] = $true
        try {
            $definition = Read-BE32 ([uint32]($object + 0x50))
            if ((Test-Mem1Pointer $definition) -and (Read-BE16 ([uint32]($definition + 0x50))) -eq 254) {
                $livePlants += [pscustomobject]@{
                    ListIndex = $index
                    Object = Format-Pointer $object
                    RomDefNo = Read-BE16 ([uint32]($object + 0x46))
                    Flags = "0x{0:X4}" -f (Read-BE16 ([uint32]($object + 0xB0)))
                }
            }
        } catch {
        }
    }
}
"  live MagicPlants: {0}" -f $livePlants.Count
$livePlants | Format-Table -AutoSize | Out-String -Width 200

"Player held-object state"
$playerObject = 0
for ($index = [int]$typeOffsets[0x00]; $index -lt [int]$typeOffsets[0x01]; $index++) {
    if (Test-Mem1Pointer $registryPointers[$index]) {
        $playerObject = $registryPointers[$index]
        break
    }
}
if (Test-Mem1Pointer $playerObject) {
    $playerExtra = Read-BE32 ([uint32]($playerObject + 0xB8))
    $heldObject = if (Test-Mem1Pointer $playerExtra) {
        Read-BE32 ([uint32]($playerExtra + 0x7F8))
    } else {
        0
    }
    "  player={0} extra={1} held={2}" -f `
        (Format-Pointer $playerObject), (Format-Pointer $playerExtra), (Format-Pointer $heldObject)
    if (Test-Mem1Pointer $heldObject) {
        try {
            $heldDefinition = Read-BE32 ([uint32]($heldObject + 0x50))
            $heldFlags = Read-BE16 ([uint32]($heldObject + 0xB0))
            $heldMemberships = @()
            for ($index = 0; $index -lt [int]$coreCounters.ObjectTypeListCount; $index++) {
                if ($registryPointers[$index] -ne $heldObject) {
                    continue
                }
                for ($candidateGroup = 0; $candidateGroup -lt 0x54; $candidateGroup++) {
                    if ($index -ge [int]$typeOffsets[$candidateGroup] -and
                        $index -lt [int]$typeOffsets[$candidateGroup + 1]) {
                        $heldMemberships += "0x{0:X2}:{1}" -f $candidateGroup, $index
                        break
                    }
                }
            }
            [pscustomobject]@{
                Object = Format-Pointer $heldObject
                Live = $liveObjectSet.ContainsKey((Format-Pointer $heldObject))
                Freed = (($heldFlags -band 0x40) -ne 0)
                Name = if (Test-Mem1Pointer $heldDefinition) {
                    Read-AsciiZ ([uint32]($heldDefinition + 0x91)) 11
                } else { "?" }
                DllId = if (Test-Mem1Pointer $heldDefinition) {
                    Read-BE16 ([uint32]($heldDefinition + 0x50))
                } else { 0xFFFF }
                RomDefNo = Read-BE16 ([uint32]($heldObject + 0x46))
                ObjFlags = "0x{0:X4}" -f $heldFlags
                MapEventSlot = [sbyte](Read-U8 ([uint32]($heldObject + 0xAC)))
                UserData2 = Read-BE32 ([uint32]($heldObject + 0xF8))
                X = Read-BEFloat ([uint32]($heldObject + 0x0C))
                Y = Read-BEFloat ([uint32]($heldObject + 0x10))
                Z = Read-BEFloat ([uint32]($heldObject + 0x14))
                Registry = $heldMemberships -join ","
            } | Format-List | Out-String -Width 200
        } catch {
            "  held-object decode failed: {0}" -f $_.Exception.Message
        }
    }
} else {
    "  no group-0 player object found"
}

"Staff-activated object group (41)"
$staffObjects = @()
for ($index = [int]$typeOffsets[0x41]; $index -lt [int]$typeOffsets[0x42]; $index++) {
    $object = $registryPointers[$index]
    if (-not (Test-Mem1Pointer $object)) {
        continue
    }
    try {
        $definition = Read-BE32 ([uint32]($object + 0x50))
        $placement = Read-BE32 ([uint32]($object + 0x4C))
        $extra = Read-BE32 ([uint32]($object + 0xB8))
        $staffObjects += [pscustomobject]@{
            Slot = $index
            Object = Format-Pointer $object
            Live = $liveObjectSet.ContainsKey((Format-Pointer $object))
            Name = if (Test-Mem1Pointer $definition) { Read-AsciiZ ([uint32]($definition + 0x91)) 11 } else { "?" }
            RomDefNo = Read-BE16 ([uint32]($object + 0x46))
            HitFlags = "0x{0:X2}" -f (Read-U8 ([uint32]($object + 0xAF)))
            ObjFlags = "0x{0:X4}" -f (Read-BE16 ([uint32]($object + 0xB0)))
            X = Read-BEFloat ([uint32]($object + 0x0C))
            Y = Read-BEFloat ([uint32]($object + 0x10))
            Z = Read-BEFloat ([uint32]($object + 0x14))
            Mode = if (Test-Mem1Pointer $placement) { Read-U8 ([uint32]($placement + 0x1C)) } else { -1 }
            SizeVariant = if (Test-Mem1Pointer $placement) { Read-U8 ([uint32]($placement + 0x1D)) } else { -1 }
            Variant = if (Test-Mem1Pointer $placement) { Read-U8 ([uint32]($placement + 0x1E)) } else { -1 }
            VariantCount = if (Test-Mem1Pointer $placement) { Read-U8 ([uint32]($placement + 0x1F)) } else { -1 }
            ActiveBit = if (Test-Mem1Pointer $placement) { Read-BES16 ([uint32]($placement + 0x22)) } else { -1 }
            LockBit = if (Test-Mem1Pointer $placement) { Read-BES16 ([uint32]($placement + 0x24)) } else { -1 }
            StateFlags = if (Test-Mem1Pointer $extra) { "0x{0:X2}" -f (Read-U8 ([uint32]($extra + 0x1D))) } else { "?" }
            TargetX = if (Test-Mem1Pointer $extra) { Read-BEFloat $extra } else { 0 }
            TargetZ = if (Test-Mem1Pointer $extra) { Read-BEFloat ([uint32]($extra + 4)) } else { 0 }
            LiftHeight = if (Test-Mem1Pointer $extra) { Read-BE32 ([uint32]($extra + 0x14)) } else { 0 }
        }
    } catch {
    }
}
$staffObjects | Select-Object Slot, Object, Live, Name, RomDefNo, HitFlags, ObjFlags, X, Y, Z |
    Format-Table -AutoSize | Out-String -Width 240
$staffObjects | Select-Object Slot, Object, Live, Mode, SizeVariant, Variant, VariantCount,
    ActiveBit, LockBit, StateFlags |
    Format-Table -AutoSize | Out-String -Width 240
$staffObjects | Select-Object Slot, Object, Live, Mode, TargetX, TargetZ, LiftHeight |
    Format-Table -AutoSize | Out-String -Width 200

"Stale registered objects (registered but absent from gObjList)"
$staleRegistered = @()
foreach ($object in ($validRegistry | Sort-Object -Unique)) {
    if ($liveObjectSet.ContainsKey((Format-Pointer $object))) {
        continue
    }
    try {
        $definition = Read-BE32 ([uint32]($object + 0x50))
        $dllId = if (Test-Mem1Pointer $definition) { Read-BE16 ([uint32]($definition + 0x50)) } else { 0xFFFF }
        $staleRegistered += [pscustomobject]@{
            Object = Format-Pointer $object
            DllId = $dllId
            RomDefNo = Read-BE16 ([uint32]($object + 0x46))
            X = Read-BEFloat ([uint32]($object + 0x0C))
            Y = Read-BEFloat ([uint32]($object + 0x10))
            Z = Read-BEFloat ([uint32]($object + 0x14))
            Placement = Format-Pointer (Read-BE32 ([uint32]($object + 0x4C)))
            Extra = Format-Pointer (Read-BE32 ([uint32]($object + 0xB8)))
        }
    } catch {
    }
}
"  stale distinct objects: {0}" -f $staleRegistered.Count
$staleRegistered | Sort-Object DllId, RomDefNo | Format-Table -AutoSize | Out-String -Width 240

"Stale registry memberships"
$staleMemberships = @()
for ($index = 0; $index -lt [int]$coreCounters.ObjectTypeListCount; $index++) {
    $object = $registryPointers[$index]
    if (-not (Test-Mem1Pointer $object) -or $liveObjectSet.ContainsKey((Format-Pointer $object))) {
        continue
    }
    $group = -1
    for ($candidateGroup = 0; $candidateGroup -lt 0x54; $candidateGroup++) {
        if ($index -ge [int]$typeOffsets[$candidateGroup] -and $index -lt [int]$typeOffsets[$candidateGroup + 1]) {
            $group = $candidateGroup
            break
        }
    }
    try {
        $definition = Read-BE32 ([uint32]($object + 0x50))
        $staleMemberships += [pscustomobject]@{
            Slot = $index
            Group = if ($group -ge 0) { "0x{0:X2}" -f $group } else { "?" }
            Object = Format-Pointer $object
            Name = if (Test-Mem1Pointer $definition) { Read-AsciiZ ([uint32]($definition + 0x91)) 11 } else { "?" }
            RomDefNo = Read-BE16 ([uint32]($object + 0x46))
            HitFlags = "0x{0:X2}" -f (Read-U8 ([uint32]($object + 0xAF)))
            ObjFlags = "0x{0:X4}" -f (Read-BE16 ([uint32]($object + 0xB0)))
        }
    } catch {
    }
}
$staleMemberships | Format-Table -AutoSize | Out-String -Width 200

"Streaming state"
$romSlots = Read-Bytes 0x8038224CL 0x40
for ($slot = 0; $slot -lt 8; $slot++) {
    $word0 = Read-BE32 ([uint32](0x8038224CL + 8 * $slot))
    $word1 = Read-BE32 ([uint32](0x80382250L + 8 * $slot))
    "  romSlot[{0}] = {1} {2}" -f $slot, (Format-Pointer $word0), (Format-Pointer $word1)
}
$loadedPages = @()
for ($slot = 0; $slot -lt 120; $slot++) {
    $page = Read-BE32 ([uint32](0x80386468L + 4 * $slot))
    if ($page -ne 0) {
        $loadedPages += "{0}:{1}" -f $slot, (Format-Pointer $page)
    }
}
"  non-null loaded romlist pages ({0}): {1}" -f $loadedPages.Count, ($loadedPages -join ", ")

""
"Heap regions (gMmRegionTable = 0x803406A0)"
$heapTable = 0x803406A0L
$allEntries = @()
for ($heapIndex = 0; $heapIndex -lt 4; $heapIndex++) {
    $descriptor = [uint32]($heapTable + 20 * $heapIndex)
    $totalBlocks = Read-BE32 $descriptor
    $usedBlocks = Read-BE32 ([uint32]($descriptor + 4))
    $entryTable = Read-BE32 ([uint32]($descriptor + 8))
    $totalSize = Read-BE32 ([uint32]($descriptor + 12))
    $usedSize = Read-BE32 ([uint32]($descriptor + 16))
    $percent = if ($totalSize -ne 0) { 100.0 * $usedSize / $totalSize } else { 0 }
    $allocationState = if ($usedBlocks + 1 -eq $totalBlocks) { "ALLOCATIONS REFUSED" } else { "allocatable" }
    "  heap[{0}] total=0x{1:X} used=0x{2:X} ({3:N2}%) slots={4}/{5} {6} entryTable={7}" -f $heapIndex, $totalSize, $usedSize, $percent, $usedBlocks, $totalBlocks, $allocationState, (Format-Pointer $entryTable)
    if (-not (Test-Mem1Pointer $entryTable) -or $totalBlocks -gt 20000) {
        continue
    }
    $blockIndex = 0
    $visited = @{}
    $chain = [System.Collections.Generic.List[int]]::new()
    $linkErrors = [System.Collections.Generic.List[string]]::new()
    $expectedPrev = 0xFFFF
    while ($blockIndex -ne 0xFFFF -and $blockIndex -lt $totalBlocks -and -not $visited.ContainsKey($blockIndex)) {
        $visited[$blockIndex] = $true
        $chain.Add($blockIndex)
        $entry = [uint32]($entryTable + 28 * $blockIndex)
        $entryPtr = Read-BE32 $entry
        $entrySize = Read-BE32 ([uint32]($entry + 4))
        $entryType = Read-BE16 ([uint32]($entry + 8))
        $prevIndex = Read-BE16 ([uint32]($entry + 10))
        $nextIndex = Read-BE16 ([uint32]($entry + 12))
        if ($prevIndex -ne $expectedPrev -and $linkErrors.Count -lt 8) {
            $linkErrors.Add(("slot {0}: prev={1}, expected={2}" -f $blockIndex, $prevIndex, $expectedPrev))
        }
        $tag = Read-BE32 ([uint32]($entry + 16))
        $ident = Read-BE32 ([uint32]($entry + 24))
        $tagHex = "{0:X8}" -f $tag
        $tagName = if ($tagNamesByHex.ContainsKey($tagHex)) { $tagNamesByHex[$tagHex] } else { "0x$tagHex" }
        $allEntries += [pscustomobject]@{
            Heap = $heapIndex
            Block = $blockIndex
            Pointer = $entryPtr
            Size = $entrySize
            Type = $entryType
            Tag = $tag
            TagName = $tagName
            Ident = $ident
        }
        $expectedPrev = $blockIndex
        $blockIndex = $nextIndex
    }
    if ($blockIndex -eq 0xFFFF) {
        $walkEnd = "end"
    } elseif ($blockIndex -ge $totalBlocks) {
        $walkEnd = "bad-index-$blockIndex"
    } else {
        $walkEnd = "cycle-at-$blockIndex"
    }
    $activeSize = [uint64]0
    foreach ($entry in ($allEntries | Where-Object { $_.Heap -eq $heapIndex })) {
        $activeSize += [uint64]$entry.Size
    }
    $nextDescriptor = "none"
    if ($usedBlocks -lt $totalBlocks) {
        $nextDescriptor = Read-BE16 ([uint32]($entryTable + 28 * $usedBlocks + 14))
    }
    "    active linked slots walked: {0}, walk={1}, covered=0x{2:X} ({3:N2}%), next descriptor={4}" -f `
        $visited.Count, $walkEnd, $activeSize, (100.0 * $activeSize / $totalSize), $nextDescriptor
    $tailStart = [Math]::Max(0, $chain.Count - 12)
    "    chain tail: {0}" -f (($chain[$tailStart..($chain.Count - 1)] | ForEach-Object { $_.ToString() }) -join ' -> ')
    if ($linkErrors.Count -ne 0) {
        "    backlink errors: {0}" -f ($linkErrors -join '; ')
    }
}

""
"Allocated GameObject candidates"
$objectCandidates = @()
foreach ($entry in ($allEntries | Where-Object {
    $_.Type -ne 0 -and $_.TagName -eq "OBJECTS_COL" -and $_.Size -ge 0x120
})) {
    $object = [uint32]$entry.Pointer
    if (-not (Test-Mem1Pointer $object)) {
        continue
    }
    try {
        $definition = Read-BE32 ([uint32]($object + 0x50))
        $romDefNo = Read-BE16 ([uint32]($object + 0x46))
        if (-not (Test-Mem1Pointer $definition) -or $romDefNo -gt 0x2000) {
            continue
        }
        $flags = Read-BE16 ([uint32]($object + 0xB0))
        $objectCandidates += [pscustomobject]@{
            Heap = $entry.Heap
            Object = Format-Pointer $object
            Size = $entry.Size
            DllId = Read-BE16 ([uint32]($definition + 0x50))
            RomDefNo = $romDefNo
            Name = Read-AsciiZ ([uint32]($definition + 0x91)) 11
            Flags = "0x{0:X4}" -f $flags
            Freed = (($flags -band 0x40) -ne 0)
            Live = $liveObjectSet.ContainsKey((Format-Pointer $object))
        }
    } catch {
    }
}
$freedCandidates = @($objectCandidates | Where-Object { $_.Freed })
$liveCandidates = @($objectCandidates | Where-Object { $_.Live })
$otherCandidates = @($objectCandidates | Where-Object { -not $_.Live -and -not $_.Freed })
"  candidates={0}, live={1}, freed-but-allocated={2}, neither-live-nor-freed={3}" -f `
    $objectCandidates.Count, $liveCandidates.Count, $freedCandidates.Count, $otherCandidates.Count
"  freed-but-allocated groups"
$freedCandidates | Group-Object Heap, DllId, RomDefNo, Name, Size | ForEach-Object {
    $first = $_.Group[0]
    [pscustomobject]@{
        Heap = $first.Heap
        DllId = $first.DllId
        RomDefNo = $first.RomDefNo
        Name = $first.Name
        SizeHex = "0x{0:X}" -f $first.Size
        Count = $_.Count
    }
} | Sort-Object Count -Descending | Format-Table -AutoSize | Out-String -Width 180

""
"Allocated bytes by tag"
$allEntries | Where-Object { $_.Type -ne 0 } |
    Group-Object Heap, TagName | ForEach-Object {
        [pscustomobject]@{
            HeapTag = $_.Name
            Blocks = $_.Count
            Bytes = ($_.Group | Measure-Object Size -Sum).Sum
        }
    } | Sort-Object Bytes -Descending | Select-Object -First 30 |
    Format-Table -AutoSize | Out-String -Width 200

"Most common live allocation sizes"
$allEntries | Where-Object { $_.Type -ne 0 } |
    Group-Object Heap, TagName, Size | ForEach-Object {
        $first = $_.Group[0]
        [pscustomobject]@{
            Heap = $first.Heap
            Tag = $first.TagName
            SizeHex = "0x{0:X}" -f $first.Size
            Size = $first.Size
            Blocks = $_.Count
            Bytes = [uint64]$first.Size * $_.Count
        }
    } | Sort-Object Blocks, Bytes -Descending | Select-Object -First 40 |
    Format-Table -AutoSize | Out-String -Width 200

"Largest allocated blocks"
$allEntries | Where-Object { $_.Type -ne 0 } | Sort-Object Size -Descending |
    Select-Object -First 30 Heap, Block,
        @{N="Pointer";E={Format-Pointer $_.Pointer}},
        @{N="SizeHex";E={"0x{0:X}" -f $_.Size}}, Size, TagName,
        @{N="Ident";E={"0x{0:X8}" -f $_.Ident}} |
    Format-Table -AutoSize | Out-String -Width 220

"Free-space summary"
$allEntries | Where-Object { $_.Type -eq 0 } | Group-Object Heap | ForEach-Object {
    [pscustomobject]@{
        Heap = $_.Name
        FreeBlocks = $_.Count
        FreeBytes = ($_.Group | Measure-Object Size -Sum).Sum
        LargestFree = ($_.Group | Measure-Object Size -Maximum).Maximum
    }
} | Format-Table -AutoSize | Out-String -Width 160
