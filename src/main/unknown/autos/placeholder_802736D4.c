#include "ghidra_import.h"
#include "main/audio/data_ref.h"
#include "main/audio/hw_volume.h"
#include "main/audio/synth_job.h"
#include "main/unknown/autos/placeholder_802736D4.h"

extern undefined4 FUN_802420b0();
extern undefined4 FUN_8028383c();
extern undefined4 FUN_80283d78();
extern undefined4 hwSaveSample();
extern undefined4 FUN_80283e00();
extern undefined4 aramQueueCallback();
extern uint aramInit();
extern undefined4 FUN_80284228();

extern void sndBegin(void);
extern void sndEnd(void);
extern void voiceBreakAndFree(u32 voice);

extern u8 lbl_803BD150[];
extern u8 dataSmpSDirTable[];
extern SynthJob synthJobTable[];
extern u32 synthFlags;
extern u16 dataKeymapNum;

extern undefined4 DAT_803bddb0;
extern undefined4 DAT_803bdfc0;
extern undefined4 DAT_803deee8;
extern undefined4 DAT_803def00;
extern undefined4 DAT_803def01;
extern f64 DOUBLE_803e8478;
extern f32 FLOAT_803e8470;
extern f32 FLOAT_803e8480;
extern f64 lbl_803E77E0;
extern f32 lbl_803E77D8;

/*
 * --INFO--
 *
 * Function: synthUpdateJobTable
 * EN v1.0 Address: 0x80272F70
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802736D4
 * EN v1.1 Size: 2168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef u32 (*SynthStreamUpdateFn)(u8* buffer, u32 length, u8* buffer2, u32 length2, u32 user);

typedef struct SynthSampleInfo {
    u32 info;
    void* addr;
    void* extraData;
    u32 offset;
    u32 length;
    u32 loop;
    u32 loopLength;
    u8 compType;
} SynthSampleInfo;

extern u8 synthJobTableCountdown;
extern u8 synthJobTablePeriod;
extern u8* synthVoice;
extern void DCInvalidateRange(void* addr, u32 size);
extern void* hwFlushStream(u8 handle);                /* gets the stream play buffer */
extern u32 hwChangeStudio(u32 voice);                 /* gets the stream playback position */
extern void hwGetPos(u8* buffer, u32 offset, u32 length, u8 handle, u32 callback, u32 user); /* flushes stream data */
extern void hwInitSamplePlayback(u32 voice, u32 keyInfo, SynthSampleInfo* sample, u32 a, s32 b, u32 voiceId, u32 c, u32 d);
extern void hwSetPitch(u32 voice, s32 pitch);
extern void hwStart(u32 voice, u8 studio);
extern void hwSetStreamLoopPS(u32 voice, u32 ps);
extern f32 lbl_803E77E8;

void synthUpdateJobTable(void)
{
    u32 cpos;
    u32 len;
    u32 off;
    SynthSampleInfo newsmp;
    u32 i;
    SynthJob* si;
    f32 volScale;
    f32 freqScale;

    if (synthJobTableCountdown != 0) {
        --synthJobTableCountdown;
        return;
    }
    synthJobTableCountdown = synthJobTablePeriod;
    freqScale = lbl_803E77E8;
    volScale = lbl_803E77D8;
    si = synthJobTable;
    for (i = 0; i < lbl_803BD150[0x210]; ++i, ++si) {
        switch (si->state) {
        case 1:
            newsmp.info = si->frq | 0x40000000;
            newsmp.addr = hwFlushStream(si->streamHandle);
            newsmp.offset = 0;
            newsmp.length = si->size;
            newsmp.loop = 0;
            newsmp.loopLength = si->size;
            si->adpcm.loopPS = si->adpcm.initialPS = *si->buffer;
            DCInvalidateRange(si->buffer, 1);
            switch (si->format) {
            case 0:
                newsmp.compType = 2;
                break;
            case 1:
                newsmp.extraData = &si->adpcm;
                newsmp.compType = 4;
                break;
            }
            hwInitSamplePlayback(si->voice, 0xFFFF, &newsmp, 1, -1,
                                 *(u32*)(synthVoice + si->voice * 0x404 + 0xF4), 1, 1);
            hwSetPitch(si->voice, freqScale * ((f32)si->frq / (f32)*(u32*)lbl_803BD150));
            hwSetVolume(si->voice, 0, volScale * si->volume, volScale * si->leftVolume,
                        volScale * si->rightVolume, si->pan << 16, si->surroundPan << 16);
            hwStart(si->voice, si->studio);
            si->state = 2;
            if (!(si->flags & 0x20000)) {
                hwGetPos(si->buffer, 0, si->bytes, si->streamHandle, 0, 0);
            }
            break;
        case 2:
            cpos = hwChangeStudio(si->voice);

            if (si->format == 1) {
                cpos = (cpos / 14) * 14;
            }

            if (si->last != cpos) {
                if (si->last < cpos) {
                    if (si->format == 1) {
                        off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off, cpos - si->last,
                                                                       0, 0, si->callbackUser)) != 0 &&
                            si->state == 2) {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000)) {
                                if (cpos == 0) {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                } else {
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                    } else if (si->format == 0) {
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2,
                                                                       cpos - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == 2) {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000)) {
                                if (cpos == 0) {
                                    hwGetPos(si->buffer, si->last * 2, (si->size - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                } else {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                    }
                } else if (cpos == 0) {
                    if (si->format == 1) {
                        off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off,
                                                                       si->size - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == 2) {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000)) {
                                if (cpos == 0) {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                } else {
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                    } else if (si->format == 0) {
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2,
                                                                       si->size - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == 2) {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000)) {
                                if (cpos == 0) {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2,
                                             si->streamHandle, 0, 0);
                                } else {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                    }
                } else {
                    if (si->format == 1) {
                        off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off,
                                                                       si->size - si->last, si->buffer,
                                                                       cpos, si->callbackUser)) != 0 &&
                            si->state == 2) {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000)) {
                                if (si->size - si->last < len) {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                    hwGetPos(si->buffer, 0, (cpos / 14) * 8, si->streamHandle, 0, 0);
                                } else if (cpos == 0) {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                } else {
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                    } else if (si->format == 0) {
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2,
                                                                       si->size - si->last, si->buffer,
                                                                       cpos, si->callbackUser)) != 0 &&
                            si->state == 2) {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000)) {
                                if (si->size - si->last < len) {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2,
                                             si->streamHandle, 0, 0);
                                    hwGetPos(si->buffer, 0, cpos * 2, si->streamHandle, 0, 0);
                                } else if (cpos == 0) {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2,
                                             si->streamHandle, 0, 0);
                                } else {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                    }
                }

                if (si->state == 2 && !(si->flags & 0x20000) && si->format == 1) {
                    hwSetStreamLoopPS(si->voice, *(u32*)((u32)si->buffer + 0x40000000) >> 24);
                }
            }
            break;
        }
    }
}

/* Pattern wrappers. */
void doNothing_802737E8(void) {}

void synthCancelJob(int voice)
{
    SynthJob *job;
    int state;

    job = synthJobTable + voice;
    state = job->state;
    if (state < 3) {
        if (state >= 1) {
            goto cancel;
        }
    }
    return;
cancel:
    if ((u32)state == 2) {
        voiceBreakAndFree(job->voice);
    }
    job->state = 3;
    job->callback(0, 0, 0, 0, job->callbackUser);
}

void synthRefreshJobVolumes(void)
{
    SynthJob *job;
    u32 i;
    f32 volumeScale;

    sndBegin();
    volumeScale = lbl_803E77D8;
    job = synthJobTable;
    for (i = 0; i < lbl_803BD150[0x210]; i++) {
        if (job->state != 0) {
            job->pan = job->savedPan;
            job->surroundPan = job->savedSurroundPan;
            if ((synthFlags & 1) != 0) {
                job->pan = 0x40;
                job->surroundPan = 0;
            } else if ((synthFlags & 2) == 0) {
                job->surroundPan = 0;
            }
            if (job->state != 3) {
                hwSetVolume(job->voice, 0, volumeScale * job->volume,
                            volumeScale * job->leftVolume, volumeScale * job->rightVolume,
                            job->pan << 0x10, job->surroundPan << 0x10);
            }
        }
        job++;
    }
    sndEnd();
}

#define DATA_KEYMAP_TAB ((DataRefEntry*)(dataSmpSDirTable + 0x4600))

int dataInsertKeymap(u16 cid, void *keymapdata)
{
    long i;
    long j;

    sndBegin();
    for (i = 0; i < dataKeymapNum && DATA_KEYMAP_TAB[i].key < cid; ++i)
        ;
    if (i < dataKeymapNum) {
        if (cid != DATA_KEYMAP_TAB[i].key) {
            if (dataKeymapNum < 256) {
                for (j = dataKeymapNum - 1; j >= i; --j)
                    DATA_KEYMAP_TAB[j + 1] = DATA_KEYMAP_TAB[j];
                ++dataKeymapNum;
            } else {
                sndEnd();
                return 0;
            }
        } else {
            DATA_KEYMAP_TAB[i].refCount++;
            sndEnd();
            return 0;
        }
    } else if (dataKeymapNum < 256) {
        ++dataKeymapNum;
    } else {
        sndEnd();
        return 0;
    }

    DATA_KEYMAP_TAB[i].key = cid;
    DATA_KEYMAP_TAB[i].data = keymapdata;
    DATA_KEYMAP_TAB[i].refCount = 1;
    sndEnd();
    return 1;
}

int dataRemoveKeymap(u32 keymapId)
{
    DataRefEntry *entry;
    u8 *tableBase;
    u16 count;
    int index;
    int moveCount;
    u32 key;
    u16 refs;

    tableBase = dataSmpSDirTable;
    sndBegin();
    count = dataKeymapNum;
    key = keymapId & 0xffff;
    entry = (DataRefEntry *)(tableBase + 0x4600);
    index = 0;
    while (index < count && entry->key != key) {
        entry++;
        index++;
    }
    if (index != count) {
        entry = (DataRefEntry *)(tableBase + 0x4600 + index * sizeof(DataRefEntry));
        refs = entry->refCount - 1;
        entry->refCount = refs;
        if (refs == 0) {
            entry = (DataRefEntry *)(tableBase + 0x4600 + (index + 1) * sizeof(DataRefEntry));
            moveCount = count - (index + 1);
            while (moveCount > 0) {
                entry[-1] = entry[0];
                entry++;
                moveCount--;
            }
            dataKeymapNum--;
            sndEnd();
            return 1;
        }
    }
    sndEnd();
    return 0;
}
