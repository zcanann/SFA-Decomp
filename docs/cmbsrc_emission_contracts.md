# CmbSrc emission and placement contracts

DLL 689's generated path remains `689_CmbSrc/CmbSrc.c`. EN owns sixteen
functions at `80236298..80237574`, the terminal descriptor at `8032BDB0`, and
the existing tables and constant pool. CmbSrc is retained as the family name;
an expansion of that abbreviation is not established.

## Activation and emission are separate

Initialization sets `active` to one unconditionally. Placement flag `0x01`
instead sets state flag `0x02`, which lets visual emission pass the check for
`OBJECT_OBJFLAG_RENDERED`. Distance limits, effect timers and the active/idle
effect selection still apply. The recovered `EMIT_WHEN_UNRENDERED` names and
setter describe that behavior without implying activation or unrestricted
emission. SC_Cloudrun sets the placement flag when creating a child and later
clears the state flag through the setter.

The former Thorntail-specific gate is a generic night gate. The sky interface's
`getSunPos` implementation at EN `8008B7F0` returns one when `timeOfDay` is at
least 75,600 or below 18,000. CmbSrc uses that result for light initialization
and activation/deactivation tests; the existing game-bit precedence is retained.

The color getter returns the cycle ordinal `0..2`, or `-1` when cycling is
disabled. CmbSrc maps those ordinals through palette indices `5, 6, 4`.
Fireball intentionally uses the returned ordinal with its own palette. The
getter's recovered name distinguishes the ordinal from the RGB palette index.

The cycle table owns three indices and a five-byte opaque tail. RGB data is two
banks of sixteen triples. The sixteen sound bytes are trigger `0x72`, represented
with the existing `SFXTRIG_mushdizzylp12` constant. Their erroneous `data:string`
annotation is removed from every version's symbol configuration.

## Two placement sizes and an uninitialized read

SC_Cloudrun requests `0x30` bytes for object `0x6E8` at EN `801DCEC4..801DCECC`.
This establishes a complete 48-byte placement contract, including the glow
projection byte at `0x2C`. EN rev1 and JP each contain 922 serialized CmbSrc
placements, all 48 bytes: 417 CmbSrc, 351 CmbSrcTPole, 147 CmbSrcTWall and
seven ThusterSour. Secondary counts do not substitute for the EN allocation
evidence.

DFP_RotateP requests only `0x2C` bytes for the same object at `802079A8`.
It stores flags `0xD2` at placement offset `0x29`, enabling both light creation
and glow. If light creation succeeds, CmbSrc reads the projection byte at
`80237370`, immediately beyond that requested record.

`Obj_AllocObjectSetup` (`8002BDF4`) clears only the requested byte count.
`mmAllocFromRegion` (`80023850`) rounds the underlying block to a multiple of
32 bytes, so the 44-byte request receives 64 bytes. The projection read reaches
uninitialized slack in that block. It is not evidence that the next allocation
is read. The source preserves the short request and the explicit byte access;
it does not initialize the extra byte or silently enlarge the request.

The separate ring-hit allocation in DFP_RotateP requests four bytes for object
`0x71C`, then initializes common placement fields beyond that request. Its
physical block is rounded to 32 bytes. That neighboring contract is recorded
here without retyping it as a CmbSrc-owned placement.

Placement byte `0x28` also has two proven roles: ordinary sources shift it left
three for the pulse distance limit, while ThusterSour divides it by 255 for a
light-pulse parameter. The owning type exposes both views at the same offset.

## Validation

The sixteen CmbSrc functions and four supporting allocator/producer/night-test
functions have equal normalized instruction signatures across the four verified
DOLs. Ten relevant allocation, flag, field-access and rounding instructions were
also compared as exact words, retaining their immediates. The 184 bytes of
tables and 108-byte constant pool are each byte-identical across the versions.
Source validation compares function bytes, sections, symbol positions and
relocations separately, then checks complete match reports, all four source
builds and the strict EN retail checksum.
