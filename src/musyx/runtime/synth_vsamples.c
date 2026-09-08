#include "musyx/synth_virtual_sample.h"
#include "musyx/hw_sample.h"
#include "musyx/hw_samplemem.h"
#include "musyx/aram.h"
#include "musyx/mcmd.h"
#include "musyx/hw_stream.h"
#include "musyx/hw_break.h"

VS vs;

/*
 * Reset the virtual sample stream buffer table.
 */
void vsInit(void) {
    int i;
    VS* state = &vs;

    state->numBuffers = 0;
    for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++) {
        state->voices[i] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
    }
    state->nextInstID = 0;
    state->callback = 0;
}

static inline void vsFreeBuffer(u8 entryIndex) {
    vs.streamBuffer[entryIndex].state = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
    vs.voices[vs.streamBuffer[entryIndex].voice] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static inline u8 vsAllocateBuffer(void) {
    u8 i;

    for (i = 0; i < vs.numBuffers; ++i) {
        if (vs.streamBuffer[i].state != SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE) {
            continue;
        }
        vs.streamBuffer[i].state = SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE;
        vs.streamBuffer[i].last = 0;
        return i;
    }

    return SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static inline u16 vsNewInstanceID(void) {
    u8 i;
    u16 instID;

    do {
        instID = vs.nextInstID++;
        for (i = 0; i < vs.numBuffers; ++i) {
            if (vs.streamBuffer[i].state != SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE &&
                vs.streamBuffer[i].info.instID == instID) {
                break;
            }
        }
    } while (i != vs.numBuffers);

    return instID;
}

/*
 * Allocate a stream buffer for the voice and set up its virtual sample
 * loop buffer.
 */
u32 vsSampleStartNotify(u8 voiceID) {
    u8 sb;
    u8 i;
    u32 addr;

    for (i = 0; i < vs.numBuffers; ++i) {
        if (vs.streamBuffer[i].state != SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE && vs.streamBuffer[i].voice == voiceID) {
            vsFreeBuffer(i);
        }
    }

    sb = vs.voices[voiceID] = vsAllocateBuffer();
    if (sb != SYNTH_VIRTUAL_SAMPLE_FREE_SLOT) {
        addr = aramGetStreamBufferAddress(vs.voices[voiceID], 0);
        hwSetVirtualSampleLoopBuffer(voiceID, addr, vs.bufferLength);
        vs.streamBuffer[sb].info.smpID = hwGetSampleID(voiceID);
        vs.streamBuffer[sb].info.instID = vsNewInstanceID();
        vs.streamBuffer[sb].smpType = hwGetSampleType(voiceID);
        vs.streamBuffer[sb].voice = voiceID;
        if (vs.callback != 0) {
            vs.callback(SYNTH_VIRTUAL_SAMPLE_CLAIM_CALLBACK_KIND, &vs.streamBuffer[sb].info);
            return (vs.streamBuffer[sb].info.instID << 8) | (u8)voiceID;
        }
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    } else {
        hwSetVirtualSampleLoopBuffer(voiceID, 0, 0);
    }

    return SYNTH_VIRTUAL_SAMPLE_INVALID_ID;
}

/*
 * Sample-completion handler: if the packed (slotIdx, smpID)
 * still matches the active sample, fire the global "done" callback
 * with kind=2, then clear the entry's mode and free the slot back to
 * the index pool.
 */
void vsSampleEndNotify(u32 packed) {
    VS* state;
    VS_BUFFER* entry;
    u32 entryOffset;
    u8* slots;
    u8 vid;
    u32 instID;

    state = &vs;
    if (packed == SYNTH_VIRTUAL_SAMPLE_INVALID_ID) {
        return;
    }
    vid = (slots = state->voices)[(u8)packed];
    if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT) {
        return;
    }
    entryOffset = vid * SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE;
    instID = (packed >> 8) & 0xffff;
    if (state->streamBuffer[vid].info.instID != instID) {
        return;
    }
    if (state->callback != NULL) {
        state->callback(SYNTH_VIRTUAL_SAMPLE_DONE_CALLBACK_KIND, &state->streamBuffer[vid].info);
    }
    entry = (VS_BUFFER*)((u8*)state->streamBuffer + entryOffset);
    entry->state = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
    slots[entry->voice] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
}

static void vsUpdateBuffer(void* entry, u32 elapsed) {
    VS* state;
    VS_BUFFER* sample;
    u32* loopSizePtr;
    struct {
        u32 len, off;
    } d; /* struct-typed pair claims target frame slot */

    state = &vs;
    sample = entry;
    if (sample->last == elapsed) {
        return;
    }
    if ((s32)sample->last < elapsed) {
        switch (sample->smpType) {
        case SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE:
            sample->info.data.update.off1 =
                (sample->last / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            sample->info.data.update.len1 = elapsed - sample->last;
            sample->info.data.update.off2 = 0;
            sample->info.data.update.len2 = 0;
            if ((d.len = state->callback(SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND, &sample->info)) != 0) {
                d.off = sample->last + d.len;
                sample->last = d.off % state->bufferLength;
            }
            break;
        default:
            break;
        }
    } else if (elapsed == 0) {
        switch (sample->smpType) {
        case SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE:
            sample->info.data.update.off1 =
                (sample->last / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = &state->bufferLength;
            sample->info.data.update.len1 = *loopSizePtr - sample->last;
            sample->info.data.update.off2 = 0;
            sample->info.data.update.len2 = 0;
            if ((d.len = state->callback(SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND, &sample->info)) != 0) {
                d.off = sample->last + d.len;
                sample->last = d.off % *loopSizePtr;
            }
            break;
        default:
            break;
        }
    } else {
        switch (sample->smpType) {
        case SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE:
            sample->info.data.update.off1 =
                (sample->last / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES;
            loopSizePtr = &state->bufferLength;
            sample->info.data.update.len1 = *loopSizePtr - sample->last;
            sample->info.data.update.off2 = 0;
            sample->info.data.update.len2 = elapsed;
            if ((d.len = state->callback(SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND, &sample->info)) != 0) {
                d.off = sample->last + d.len;
                sample->last = d.off % *loopSizePtr;
            }
            break;
        default:
            break;
        }
    }
}

#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE 0xa0
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND 0xfff
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT 0x1000

/*
 * Periodic virtual-sample tick processor: walks 64 active voices, computes
 * elapsed tick for each, and either advances the stream buffer (state 1)
 * or runs sample-completion logic (state 2 - checks current sample
 * id matches expected and triggers a stop+vacate when threshold
 * elapsed).
 */
void vsSampleUpdates(void) {
    VS* state;
    u8* slotMap;
    u32 i;
    u32 currentTick;
    u32 elapsed;
    VS_BUFFER* entry;
    u8 vid;

    if (vs.callback != 0) {
        state = &vs;
        slotMap = (u8*)state;
        for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++, slotMap++) {
            vid = slotMap[offsetof(VS, voices)];
            if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT) {
                continue;
            }
            if (hwGetVirtualSampleState(i) == 0) {
                continue;
            }
            vid = slotMap[offsetof(VS, voices)];
            entry = &state->streamBuffer[vid];

            currentTick = hwChangeStudio(i);
            if (entry->smpType == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE) {
                elapsed =
                    (currentTick / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) * SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES;
            } else {
                elapsed = currentTick;
            }

            switch (entry->state) {
            case SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE:
                vsUpdateBuffer(entry, elapsed);
                break;
            case SYNTH_VIRTUAL_SAMPLE_MODE_DONE_WAIT: {
                u32 smpID = hwGetVirtualSampleID(entry->voice);
                u32 expected = ((u32)entry->info.instID << 8) | entry->voice;

                if (expected == smpID) {
                    u32 prev;

                    vsUpdateBuffer(entry, elapsed);
                    prev = entry->finalLast;
                    if (currentTick >= prev) {
                        entry->finalGoodSamples -= (currentTick - prev);
                    } else {
                        entry->finalGoodSamples -= state->bufferLength - (prev - currentTick);
                    }
                    entry->finalLast = currentTick;

                    if ((s32)(u32)((s32)(synthVoice[entry->voice].curPitch * SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE +
                                         SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND) /
                                   SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT) > (s32)entry->finalGoodSamples) {
                        if (hwVoiceInStartup(entry->voice) == 0) {
                            hwBreak(entry->voice);
                        }
                        entry->state = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                        state->voices[entry->voice] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
                    }
                } else {
                    entry->state = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                    state->voices[entry->voice] = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
                }
            } break;
            }
        }
    }
}
