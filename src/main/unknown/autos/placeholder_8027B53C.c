#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027B53C.h"

typedef struct SynthLoadedGroupEntry {
    u8 *header;
    u32 sdi;
    u8 *base;
} SynthLoadedGroupEntry;

extern int fn_8026C488(u8 *a, u8 *b, u8 *c, u32 d, u32 e, u32 f, u32 groupId);
extern void sndBegin(void);
extern void sndEnd(void);
extern u32 hwInitStream(u32 stream);
extern int audioLoadSdiFile(u32 sdi, u32 streamHandle);
extern void hwSyncSampleMem(void);
extern int dataAddFXGroup(u16 groupId, u16 *fxData, u16 count);

extern u8 gSynthInitialized;
extern s16 synthLoadedGroupCount;
extern SynthLoadedGroupEntry synthLoadedGroupTable[];

/*
 * audioFn_8027b42c - large voice-update inner helper (~152 instructions).
 * Stubbed pending full decode.
 */
#pragma dont_inline on
void audioFn_8027b42c(u16 voiceId, u16 a, u16 b, u16 c)
{
    (void)voiceId;
    (void)a;
    (void)b;
    (void)c;
}
#pragma dont_inline reset

/*
 * Iterate a u16 list terminated by 0xFFFF, dispatching each entry to
 * audioFn_8027b42c. Entries with bit 0x8000 set are ranges: low 14 bits
 * are the start, the following u16 is the inclusive end.
 *
 * EN v1.0 Address: 0x8027B260
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027B690
 * EN v1.1 Size: 156b
 */
#pragma dont_inline on
void fn_8027B690(u16 *list, u16 a, u16 b, u16 c)
{
    while (*list != 0xffff) {
        u16 v = *list;
        if ((v & 0x8000) != 0) {
            u16 i = v & 0x3fff;
            for (; (u32)i <= (u32)list[1]; i++) {
                audioFn_8027b42c(i, a, b, c);
            }
            list += 2;
        } else {
            v = *list;
            list++;
            audioFn_8027b42c(v, a, b, c);
        }
    }
}
#pragma dont_inline reset

/*
 * Register a sound group, load its stream directory, and fan out its
 * voice/event lists into the synth data tables.
 */
int sndPushGroup(u8 *groupBase, u32 groupId, u32 stream, u32 sdi, u32 tableSet)
{
    s16 slot;
    u8 *group;
    SynthLoadedGroupEntry *entry;
    u8 *preloadList;

    if (gSynthInitialized == 0) {
        return 0;
    }

    slot = synthLoadedGroupCount;
    if (slot >= 0x80) {
        return 0;
    }

    group = groupBase;
    while (*(s32 *)group != -1) {
        if (*(u16 *)(group + 4) == (u16)groupId) {
            entry = &synthLoadedGroupTable[slot];
            entry->header = group;
            entry->base = groupBase;
            entry->sdi = sdi;

            preloadList = groupBase + *(u32 *)(group + 0xc);
            if (audioLoadSdiFile(sdi, hwInitStream(stream)) != 0) {
                fn_8027B690((u16 *)preloadList, sdi, 1, 0);
            }
            fn_8027B690((u16 *)(groupBase + *(u32 *)(group + 8)), tableSet, 0, 0);
            fn_8027B690((u16 *)(groupBase + *(u32 *)(group + 0x10)), tableSet, 4, 0);
            fn_8027B690((u16 *)(groupBase + *(u32 *)(group + 0x14)), tableSet, 2, 0);
            fn_8027B690((u16 *)(groupBase + *(u32 *)(group + 0x18)), tableSet, 3, 0);
            if (*(u16 *)(group + 6) == 1) {
                u16 *fxData = (u16 *)(groupBase + *(u32 *)(group + 0x1c));
                dataAddFXGroup(groupId, fxData + 2, fxData[0]);
            }
            hwSyncSampleMem();
            synthLoadedGroupCount++;
            return 1;
        }
        group = groupBase + *(s32 *)group;
    }
    return 0;
}

/*
 * Find a loaded group/sample entry and start it through the synth scheduler.
 */
int fn_8027B89C(u32 groupId, u16 sampleId, u32 a, u32 b, u8 noLock, u32 c)
{
    s16 i;
    u8 *group;
    u8 *base;
    u8 *tableA;
    u8 *tableB;
    u8 *sample;
    int result;

    for (i = 0; i < synthLoadedGroupCount; i++) {
        group = synthLoadedGroupTable[i].header;
        if ((u16)groupId == *(u16 *)(group + 4)) {
            if (*(u16 *)(group + 6) != 0) {
                return -1;
            }
            base = synthLoadedGroupTable[i].base;
            tableA = base + *(u32 *)(group + 0x1c);
            tableB = base + *(u32 *)(group + 0x20);
            sample = base + *(u32 *)(group + 0x24);
            while (*(u16 *)sample != 0xffff) {
                if (*(u16 *)sample == sampleId) {
                    if (noLock != 0) {
                        return fn_8026C488(tableA, tableB, sample, a, b, c, groupId);
                    }
                    sndBegin();
                    result = fn_8026C488(tableA, tableB, sample, a, b, c, groupId);
                    sndEnd();
                    return result;
                }
                sample += 0x54;
            }
            return -1;
        }
    }
    return -1;
}

/*
 * Thin wrapper inserting 0 as the no-lock flag into fn_8027B89C and
 * shifting the caller's last arg into position.
 *
 * EN v1.0 Address: 0x8027B26C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027B9DC
 * EN v1.1 Size: 36b
 */
int fn_8027B9DC(u32 groupId, u16 sampleId, u32 a, u32 b, u32 c)
{
    return fn_8027B89C(groupId, sampleId, a, b, 0, c);
}
