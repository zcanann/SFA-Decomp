# Timer controls and revision differences

DLL 693 owns the EN text at `8023852C..80238AB0`, the terminal 56-byte
descriptor at `8032BEC0..8032BEF8`, two floats at `803DC418..803DC420`, and
32 constant-pool bytes at `803E7408..803E7428`. Its generated
`693_Timer/Timer.c` path and splits remain unchanged.

The shared `gameTimerInit` argument is seconds, converted to nominal frames
by multiplication by 60. Its first argument is a flags field, not a timer ID:
count down, count up, loop sound, end sound, and display occupy bits 0 through
4. Initialization pauses the timer. The former `timerSetToCountUp` only clears
that pause; `gameTimerResume` describes its actual behavior. Direction remains
in the separate flags field. All direct callers now use the shared flags and
correct units, including the SnowHorn controller and DR generator fields.

The object's allocation is 32 bytes. Its countdown is in nominal frames;
`timer_addDuration` adds frames only to an already nonzero countdown. Restarting
the global display truncates that countdown to whole seconds. Initializing the
object countdown retains the signed-16 narrowing of `durationSeconds * 60`.
The field at state offset eight is only observed receiving `0.04f`; its old
light-scale interpretation is unsupported and it remains opaque.

The placement reader accesses through offset `0x21`: mode at `0x19`, signed
seconds at `0x1A`, completion bit at `0x1E`, and start bit at `0x20`. No full EN
placement extent is established. Independently scanned EN rev1 and JP assets
each contain 20 records of 36 bytes: 15 CNTstopwatc (`0x6BC`) and five Timer
(`0x750`). Those secondary records do not establish an EN allocation size.

Cancellation and natural expiry both latch `ended`. Only natural expiry writes
the completion game bit. Starting again does not clear the latch.
`timer_clearStartAndEndFlags` clears the start override and ended latch without
resetting the countdown. A forced start bypasses cancellation by the start bit.
Freeing either mode stops the shared global timer. The excluded cancellation
sound value `0x466ED` is a placement identity, not a map ID.

Effect mode uses the canonical light's `glowType` and `enabled` bytes. Its
texture phase follows duration divided by remaining frames, not linear elapsed
progress. The previous phase flag stores only one bit. Retail's read of an
uninitialized texture ID when the light exists but texture lookup fails remains
explicitly documented and preserved.

Two genuine revision differences explain the remaining timer code mismatches:

| Function | EN / JP | EN rev1 / PAL rev1 |
| --- | --- | --- |
| `timer_update` | 780 bytes | 832 bytes; adds a global-mode disabled check |
| `gameTimerRun` | 1376 bytes | 1388 bytes; guards loop-sound keepalive with nonzero frame delta |

The 13-instruction object insertion compares `isGameTimerDisabled() == 1`.
All four retail helpers return the raw disabled mask, zero or two, so the
added check is inert. Preserve that comparison rather than repairing the
retail bug. The three-instruction shared-helper insertion suppresses only
sound keepalive while paused; volume and pan updates still run.

Both functions now match exactly in EN rev1 and PAL rev1, adding 2,220 matched
code bytes and two exact functions per revision. Timer's ten functions and all
96 data bytes match in all four versions. Only Timer is promoted in the two
regional manifests: modelEngine's code is exact but its existing regional data
mismatches remain.

Seventeen other owner/helper normalized instruction signatures agree across
the four verified DOLs, as do the owner's two floats and 32-byte constant pool.
The shared semantic changes preserve EN and JP code, data, symbol layouts and
relocations after the three explicit API renames. In the two later revisions,
only the two recovered function bodies change; data and other function bodies
remain unchanged. Full four-version source builds and objdiff reports and the
strict EN retail checksum gate the change. Compiler profiles are unchanged.
