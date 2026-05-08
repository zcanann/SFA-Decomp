#include "src/main/audio/synth_internal.h"

/*
 * fn_8026DDB4: parse a 1-or-2-byte unsigned event tag (out into u16* at r4)
 * followed by a 1-or-2-byte signed value (sign-extended low 7 / 14 bits, out
 * into u16* at r5). Returns the advanced read pointer, or NULL when the tag
 * is the sentinel 0x80 0x00.
 */
u8* fn_8026DDB4(u8* p, u16* tagOut, u16* valueOut) {
    u8 b1;
    u8 b2;

    b1 = p[0];
    b2 = p[1];
    if (b1 == 0x80 && b2 == 0) {
        return 0;
    }

    if (b1 & 0x80) {
        *tagOut = (u16)(((b1 & 0x7F) << 8) | b2);
        p += 2;
    } else {
        *tagOut = (u16)b1;
        p += 1;
    }

    {
        u8 b3 = p[0];
        u8 b4 = p[1];
        int shift;
        s16 v;

        if (b3 & 0x80) {
            v = (s16)(u16)(((b3 & 0x7F) << 8) | b4);
            shift = 1;
            v = (s16)((s16)((s16)v << shift) >> shift);
            *valueOut = (u16)v;
            p += 2;
            return p;
        }

        v = (s16)(u16)b3;
        shift = 9;
        v = (s16)((s16)((s16)v << shift) >> shift);
        *valueOut = (u16)v;
        p += 1;
        return p;
    }
}
