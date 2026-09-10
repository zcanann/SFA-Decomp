# Camera viewport height across retail versions

The four camera viewport functions use XFB height in EN v1.0 and JP, and EFB
height in EN rev1 and both PAL revisions. This is the same version distinction
as video initialization. `main/video_viewport.h` now supplies the shared
`VIDEO_VIEWPORT_HEIGHT` selection to both source units.

Each function has two paths, calling either `GXSetViewportJitter` or
`GXSetViewport`. Direct reads from all five checksum-verified input DOLs establish
all forty height-load instructions: `lhz r0,8(r4)` in EN/JP and
`lhz r0,6(r4)` in the other versions. These offsets are `xfbHeight` and
`efbHeight` in `GXRenderModeObj`. The functions are:

- `Camera_ApplyFullViewport`
- `Camera_ApplyEffectDepthViewport`
- `Camera_ApplyTransparentViewport`
- `Camera_ApplyDecalViewport`

The accessor is an expression macro that evaluates its argument once. A static
inline function preserved camera code but changed evaluation and register
allocation in `videoInit`; the macro preserves the original member-access
expression there. No compiler setting, depth range, jitter selection or render
mode layout changes.

The complete camera object changes in exactly eight bytes per affected version,
all selecting offset 6 instead of 8 in those loads. This preserves every other
instruction byte, relocation, data section, symbol position and object record.
EN and JP camera objects remain byte-identical, as do all five video-init
objects. The three affected versions gain four exact functions (752 bytes)
each and one completed camera unit. Each camera unit has all 58 functions
(8,472 bytes) and all 6,580 data bytes exact.

All five `all_source` builds pass. In every version, an all-retail control and a
link substituting both camera and video-init source reproduce the verified
original DOL; the native strict checksum target also passes. Every unrelated
source object is unchanged. The affected regional manifests now include
`main/camera.c`; EN and JP retain their existing completion claims.
