#include "src/main/audio/synth_internal.h"

extern void fn_80271b4c(u32 value0, u32 value1, u8 studio, u8 mode, u32 handle);

/*
 * sndSeqVolume backend. Resolves a sequence handle across queued and active
 * voices; active voices update immediately, queued voices cache a pending
 * studio-volume change until they are started.
 *
 * EN v1.0 Address: 0x8026D6E4, size 0x19C
 */
void fn_8026D6E4(u32 value0, u32 value1, u32 handle, u32 mode) {
    SynthVoice* voice;
    SynthVoice* voiceBase;
    u32 voiceIndex;
    u32 studioIndex;

    voiceBase = gSynthVoices;
    for (voice = gSynthQueuedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & 0x7FFFFFFF)) {
            studioIndex = (handle & 0x80000000) | voice->slotIndex;
            goto resolved;
        }
    }

    for (voice = gSynthAllocatedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & 0x7FFFFFFF)) {
            studioIndex = (handle & 0x80000000) | voice->slotIndex;
            goto resolved;
        }
    }

    studioIndex = 0xFFFFFFFF;

resolved:
    if (studioIndex != 0xFFFFFFFF) {
        if ((studioIndex & 0x80000000) == 0) {
            fn_80271b4c(value0, value1, gSynthVoices[studioIndex].currentStudio, mode, handle);
            voice = &gSynthVoices[studioIndex];
            voiceIndex = 0;
            do {
                if (voice->studioMap[voiceIndex] != gSynthVoices[studioIndex].currentStudio) {
                    fn_80271b4c(value0, value1, voice->studioMap[voiceIndex], 0, 0xFFFFFFFF);
                }
                voiceIndex++;
            } while (voiceIndex < SYNTH_SEQUENCE_TRACK_COUNT);
        } else {
            mode &= 0xF;
            voiceIndex = studioIndex & 0x7FFFFFFF;
            if (mode == 2) {
                voiceBase[voiceIndex].pendingUpdate.flags |= 8;
                voiceBase[voiceIndex].pendingUpdate.studio = (u8)value0;
            } else if (mode < 2) {
                if (mode == 0) {
                    voiceBase[voiceIndex].pendingUpdate.studio = (u8)value0;
                } else {
                    voiceBase[voiceIndex].pendingUpdate.output = 0;
                }
            } else if (mode < 4) {
                voiceBase[voiceIndex].pendingUpdate.flags |= 0x80;
                voiceBase[voiceIndex].pendingUpdate.studio = (u8)value0;
            }
        }
    }
}

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
