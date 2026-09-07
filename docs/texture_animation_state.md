# Texture animation units and modes

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

The first texture in a loaded animation stores `frameCount << 8` in its
halfword at +0x10. The canonical field is now `animationFrameCountFixed`:
it is the upper bound for an 8.8 frame accumulator, not an integer count.
The loader still writes the literal value 1 to later chain nodes, and
`textureAlloc` uses that same value for individually allocated textures.
Those existing sentinel-like values are retained.

`animationFrameStep` at +0x14 is the 8.8 increment multiplied by
`framesThisStep`. `textureGetAnimationFrame` clamps against the fixed-point
limit, shifts by eight, and walks `nextAnimationFrame`. The environment
updater and engine slot 11 now use the renamed count field. The game UI's
blink initializer names its existing reverse-playback flag.

The four recovered flags are owned by `texture.h` alongside the animation
API declarations:

| Flag | Value | Observed behavior |
| --- | --- | --- |
| `TEXTURE_ANIM_REVERSE` | 0x80000 | Subtract the frame step; select the preceding frame in the pair selector. |
| `TEXTURE_ANIM_PING_PONG` | 0x40000 | Reflect at the animation endpoints. In random-start mode this bit also marks an active playback cycle. |
| `TEXTURE_ANIM_RANDOM_START` | 0x20000 | Wait for `randomGetRange(0, 1000) > 985`, then play forward and back once. |
| `TEXTURE_ANIM_SELECT_NEXT` | 0x40 | Bind a neighboring animation frame as the second texture instead of reusing the first. |

Random-start playback clears the reverse bit and sets the ping-pong bit on
trigger. When its return leg crosses below zero it clamps to zero and clears
both bits. An excessive forward step that reflects below zero takes the
same completion path. Continuous ping-pong instead repeats reflection until
the accumulator is in range. Its lower reflection is `-frame`, while its
upper reflection is `2 * limit - 1 - frame`; that asymmetry remains intact.
Ordinary forward and reverse playback wrap by the fixed-point limit.

The pair selector takes its integer frame index from the upper 16 bits of
its packed argument. This is a distinct interface from the 8.8 accumulator;
the low half is not read by the selector. Its endpoint behavior is also
distinct: without ping-pong it clamps the neighboring index rather than
wrapping it. A forced texture overrides only the second binding. The source
retains all these behaviors and the unused arguments.

Validation: all 1,002 source objects are byte-identical and the complete
objdiff report is unchanged. The updater, step setter, frame lookup, and
pair selector remain 100% matched. Both the strict retail checksum build
and `ninja all_source` pass.
