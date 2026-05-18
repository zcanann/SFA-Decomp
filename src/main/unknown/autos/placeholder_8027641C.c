#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027641C.h"

extern u8 *dataGetCurve(u16 keyId);
extern void sndConvertMs(u32 *p);
extern void sndConvertTicks(u32 *p, McmdVoiceState *state);
extern int sndConvert2Ms(u32 v);

/*
 * Linear-interpolated table lookup: value's high u16 selects entry,
 * low u16 is the fractional weight between entry[hi] and entry[hi+1].
 *
 * EN v1.0 Address: 0x802763C0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027641C
 * EN v1.1 Size: 124b
 */
u32 fn_802763C0(u32 value, u16 keyId)
{
    u8 *table;
    u32 a;
    u32 b;
    u32 lo;
    u32 hi;
    u32 result;

    result = value;
    if (keyId != 0xffff) {
        table = dataGetCurve(keyId);
        if (table != NULL) {
            hi = result >> 16;
            lo = result & 0xffff;
            if (hi < 0x7f) {
                a = table[hi];
                b = table[hi + 1];
                result = (a << 16) + lo * (b - a);
            } else {
                result = (u32)table[hi] << 16;
            }
        }
    }
    return result;
}

/*
 * Compute envelope step: scale + interpolate via table, store target/
 * time/step into state, mark state dirty.
 *
 * EN v1.0 Address: 0x80276440
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80276440
 * EN v1.1 Size: 296b
 */
void mcmdScaleVolume(McmdVoiceState *state, McmdCommandArgs *params, u32 volumeStart)
{
    u32 t;
    int divisor;
    u32 scaled;
    u32 keyId;
    u8 *table;
    u32 p0;
    u32 hi;
    u32 lo;
    u32 a;
    u32 b;
    u32 dirtyFlag;

    t = params->value >> 16;
    if ((params->value >> 8) & 1) {
        sndConvertMs(&t);
    } else {
        sndConvertTicks(&t, state);
    }
    divisor = sndConvert2Ms(t);
    if (divisor == 0) {
        divisor = 1;
    }

    p0 = params->flags;
    hi = (p0 >> 8) & 0xff;
    scaled = (state->volume * hi) >> 7;
    scaled += (p0 & 0xff0000);
    if (scaled > 0x7f0000) {
        scaled = 0x7f0000;
    }
    keyId = p0 >> 24;
    keyId |= (params->value & 0xff) << 8;

    if ((u16)keyId != 0xffff) {
        table = dataGetCurve(keyId);
        if (table != NULL) {
            hi = scaled >> 16;
            lo = scaled & 0xffff;
            if (hi < 0x7f) {
                a = table[hi];
                b = table[hi + 1];
                scaled = lo * (b - a) + (a << 16);
            } else {
                scaled = (u32)table[hi] << 16;
            }
        }
    }

    state->volumeTarget = scaled;
    state->volumeStart = volumeStart;
    state->volumeStep = (s32)(scaled - volumeStart) / divisor;
    state->volume = volumeStart;
    dirtyFlag = MCMD_VOICE_VOLUME_RAMP_OUTPUT_FLAG;
    state->outputFlags |= dirtyFlag;
}
