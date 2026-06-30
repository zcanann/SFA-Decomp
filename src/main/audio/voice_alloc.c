#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/voice_manage.h"
#include "main/audio/mcmd_exec.h"
extern VoiceIdSlot voiceFreeListSlots[];
extern u8* synthVoice;
extern u8 lbl_803BD150[];
extern u8 synthIdleWaitActive;
extern u16 voicePrioSortRootListRoot;
extern u8 voiceMusicRunning;
extern u8 voiceFxRunning;
extern u8 voiceListInsert;
extern u8 voiceListRoot;

typedef struct SynthRootListNode
{
    u16 next;
    u16 prev;
} SynthRootListNode;

typedef struct SynthVoiceListNode
{
    u8 prev;
    u8 next;
    u16 user;
} SynthVoiceListNode;

typedef struct VidListTables
{
    u8 vidLists[0x800];
    u8 midiKeySlots[0x80];
    u8 directSlots[0x40];
    SynthVoiceListNode priorityLinks[0x40];
    u8 priorityGroupHeads[0x100];
    SynthRootListNode prioritySortLinks[0x100];
    SynthVoiceListNode freeList[0x40];
} VidListTables;

extern u8 vidListNodes[];

typedef struct AllocVoice
{
    u8 pad000[0x100];
    u16 allocId;
    u8 pad102[0xA];
    u8 prio;
    u8 pad10D[3];
    u32 age;
    u32 cFlagsHi;
    u32 cFlagsLo;
    u8 block;
    u8 fxFlag;
    u8 pad11E[0x404 - 0x11E];
} AllocVoice;

#define ALLOC_VOICE ((AllocVoice*)synthVoice)
#define VOICE_CFLAGS(i) (*(u64*)&ALLOC_VOICE[i].cFlagsHi)

#define VB_PRIO_HEAD(vb, p) \
    (*(u8*)((u8*)&(vb)->priorityGroupHeads[0] + (p)))
#define VB_PRIO_LINK_NEXT(vb, i) \
    (((SynthVoiceListNode*)((u8*)&(vb)->priorityLinks[0] + (i) * 4))->next)
#define VB_PRIO_SORT_NEXT(vb, p) \
    (((SynthRootListNode*)((u8*)&(vb)->prioritySortLinks[0] + (p) * 4))->next)
#define AV_PRIO(i)   (*(u8*)((u8*)&ALLOC_VOICE[0].prio + (i) * 0x404))
#define AV_FXFLAG(i) (*(u8*)((u8*)&ALLOC_VOICE[0].fxFlag + (i) * 0x404))

/*
 * Allocate a voice id, preferring a free slot but stealing the lowest-priority
 * compatible active voice when limits are exceeded. (musyx synthvoice.c
 * voiceAllocate, pre-2.0.1 variant.)
 */
u32 voiceAllocate(u8 priority, u8 maxVoices, u16 allocId, u8 fxFlag)
{
    s32 i;
    u32 type_alloc;
    u16 p;
    s32 num;
    s32 voice;
    SynthVoiceListNode* sfv;
    VidListTables* vb = (VidListTables*)vidListNodes;

    if (!synthIdleWaitActive)
    {
        if (fxFlag)
        {
            type_alloc = (voiceFxRunning >= lbl_803BD150[0x212] &&
                lbl_803BD150[0x210] > lbl_803BD150[0x212]);

            if (lbl_803BD150[0x212] <= maxVoices)
            {
                goto _skip_alloc;
            }

            goto _do_alloc;
        }
        else
        {
            type_alloc = (voiceMusicRunning >= lbl_803BD150[0x211] &&
                lbl_803BD150[0x210] > lbl_803BD150[0x211]);

            if (lbl_803BD150[0x211] <= maxVoices)
            {
                goto _skip_alloc;
            }

        _do_alloc:
            num = 0;
            voice = -1;

            p = voicePrioSortRootListRoot;
            while (p != 0xFFFF && priority >= p && voice == -1)
            {
                for (i = VB_PRIO_HEAD(vb, p); i != 0xff;
                     i = VB_PRIO_LINK_NEXT(vb, i))
                {
                    if (allocId != ALLOC_VOICE[i].allocId)
                        continue;
                    ++num;
                    if (ALLOC_VOICE[i].block)
                        continue;

                    if (!type_alloc || fxFlag == ALLOC_VOICE[i].fxFlag)
                    {
                        if (VOICE_CFLAGS(i) & 2)
                            continue;
                        if (voice != -1)
                        {
                            if (ALLOC_VOICE[i].age < ALLOC_VOICE[voice].age)
                                voice = i;
                        }
                        else
                            voice = i;
                    }
                }

                p = VB_PRIO_SORT_NEXT(vb, p);
            }
        }

        if (num < maxVoices)
        {
            while (p != 0xffff && num < maxVoices)
            {
                i = VB_PRIO_HEAD(vb, p);
                while (i != 0xff)
                {
                    if (allocId == ALLOC_VOICE[i].allocId)
                    {
                        num++;
                    }

                    i = VB_PRIO_LINK_NEXT(vb, i);
                }

                p = VB_PRIO_SORT_NEXT(vb, p);
            }

            if (num < maxVoices)
            {
            _skip_alloc:
                voice = -1;
                if (voiceListRoot != 0xff && type_alloc == 0)
                {
                    voice = voiceListRoot;
                    goto _update;
                }

                if (priority < voicePrioSortRootListRoot)
                {
                    return -1;
                }

                p = voicePrioSortRootListRoot;

                while (p != 0xFFFF && priority >= p && voice == -1)
                {
                    for (i = VB_PRIO_HEAD(vb, p); i != 0xff;
                         i = VB_PRIO_LINK_NEXT(vb, i))
                    {
                        if (ALLOC_VOICE[i].block != 0)
                            continue;

                        if (!type_alloc || fxFlag == ALLOC_VOICE[i].fxFlag)
                        {
                            if (VOICE_CFLAGS(i) & 2)
                                continue;
                            if (voice != -1)
                            {
                                if (ALLOC_VOICE[voice].age > ALLOC_VOICE[i].age)
                                    voice = i;
                            }
                            else
                                voice = i;
                        }
                    }
                    p = VB_PRIO_SORT_NEXT(vb, p);
                }

                if (voice == -1)
                {
                    return 0xffffffff;
                }

            _update:
                if (AV_PRIO(voice) > priority)
                {
                    goto _fail;
                }
            }
        }

        if (voice == -1)
        {
            goto _fail;
        }

        if (vb->freeList[voice].user == 1)
        {
            sfv = vb->freeList + voice;
            i = sfv->prev;

            if (i != 0xff)
            {
                vb->freeList[i].next = sfv->next;
            }
            else
            {
                voiceListRoot = sfv->next;
            }

            i = sfv->next;
            if (i != 0xff)
            {
                vb->freeList[i].prev = sfv->prev;
            }

            if (voice == voiceListInsert)
            {
                voiceListInsert = sfv->prev;
            }

            sfv->user = 0;
        }
        else if (AV_FXFLAG(voice))
        {
            voiceFxRunning--;
        }
        else
        {
            voiceMusicRunning--;
        }
        if (fxFlag != 0)
        {
            ++voiceFxRunning;
        }
        else
        {
            ++voiceMusicRunning;
        }
        return voice;
    }

_fail:
    return -1;
}

/*
 * Release a voice slot: clear voice flags, unlink from id table,
 * decrement counter, and mark id slot as free (-1).
 *
 * EN v1.1 Address: 0x80279B98, size 228b
 */
void voiceFree(int state)
{
    McmdVoiceState* vs = (McmdVoiceState*)state;
    macMakeInactive((McmdVoiceState*)state, 2);
    voiceRemovePriority(state);
    *(u32*)&vs->macroBase = 0;
    vs->priorityGroup = 0;
    {
        u32 voice = vs->voiceHandle;
        u32 v = voice & 0xff;
        VoiceIdSlot* slot = &voiceFreeListSlots[v];
        if (slot->active == 0)
        {
            slot->active = 1;
            if (voiceListRoot != 0xff)
            {
                slot->next = 0xff;
                slot->prev = voiceListInsert;
                voiceFreeListSlots[voiceListInsert].next = v;
            }
            else
            {
                slot->next = 0xff;
                slot->prev = 0xff;
                voiceListRoot = v;
            }
            voiceListInsert = v;
            if (vs->streamKind != 0)
            {
                voiceFxRunning--;
            }
            else
            {
                voiceMusicRunning--;
            }
        }
    }
    *(int*)&vs->voiceHandle = -1;
}
