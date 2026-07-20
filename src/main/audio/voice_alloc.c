#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/voice_manage.h"
#include "main/audio/mcmd_exec.h"
#include "main/audio/vidlisttables.h"
#include "main/audio/synth_config.h"
#include "main/audio/voice_alloc.h"
#include "main/audio/voice_id.h"
#include "main/audio/vid_init.h"


#define VOICE_CFLAGS(i) (*(u64*)&synthVoice[i].inputFlags)

#define VB_PRIO_HEAD(vb, p)      (*(u8*)((u8*)&(vb)->priorityGroupHeads[0] + (p)))
#define VB_PRIO_LINK_NEXT(vb, i) (((SynthVoiceListNode*)((u8*)&(vb)->priorityLinks[0] + (i) * 4))->next)
#define VB_PRIO_SORT_NEXT(vb, p) (((SynthRootListNode*)((u8*)&(vb)->prioritySortLinks[0] + (p) * 4))->next)
#define AV_PRIO(i)               (synthVoice[i].priorityGroup)
#define AV_FXFLAG(i)             (synthVoice[i].streamKind)

SynthVoiceListNode voiceFreeListSlots[64];
extern u8 synthIdleWaitActive;
/*
 * Allocate a voice id, preferring a free slot but stealing the lowest-priority
 * compatible active voice when limits are exceeded. (musyx synthvoice.c
 * voiceAllocate, pre-2.0.1 variant.)
 */
u32 voiceAllocate(u8 priority, u8 maxVoices, u16 allocId, u8 fxFlag)
{
    s32 i;
    s32 num;
    s32 voice;
    u16 prioNode;
    u32 type_alloc;
    u32 pn3;
    SynthVoiceListNode* sfv;
    SynthVoiceListNode* fl;
    VidListTables* vb = (VidListTables*)vidListNodes;

    if (!synthIdleWaitActive)
    {
        if (fxFlag)
        {
            type_alloc = (voiceFxRunning >= SYNTH_CONFIGURATION->fxVoiceCount &&
                          SYNTH_CONFIGURATION->voiceCount > SYNTH_CONFIGURATION->fxVoiceCount);

            if (SYNTH_CONFIGURATION->fxVoiceCount <= maxVoices)
                goto steal;
        }
        else
        {
            type_alloc = (voiceMusicRunning >= SYNTH_CONFIGURATION->musicVoiceCount &&
                          SYNTH_CONFIGURATION->voiceCount > SYNTH_CONFIGURATION->musicVoiceCount);

            if (SYNTH_CONFIGURATION->musicVoiceCount <= maxVoices)
                goto steal;
        }

        {
            num = 0;
            voice = -1;

            prioNode = voicePrioSortedRoot;
            while (prioNode != 0xFFFF && priority >= prioNode && voice == -1)
            {
                u32 pn1 = prioNode;
                for (i = VB_PRIO_HEAD(vb, pn1); i != 0xff; i = VB_PRIO_LINK_NEXT(vb, i))
                {
                    if (allocId != synthVoice[i].baseSample)
                        continue;
                    ++num;
                    if (synthVoice[i].block)
                        continue;

                    if (!type_alloc || fxFlag == synthVoice[i].streamKind)
                    {
                        if (VOICE_CFLAGS(i) & 2)
                            continue;
                        if (voice != -1)
                        {
                            if (synthVoice[i].priorityValue < synthVoice[voice].priorityValue)
                                voice = i;
                        }
                        else
                            voice = i;
                    }
                }

                prioNode = VB_PRIO_SORT_NEXT(vb, pn1);
            }

            if (num >= maxVoices)
                goto have_voice;

            while (prioNode != 0xffff && num < maxVoices)
            {
                u32 pn = prioNode;
                i = VB_PRIO_HEAD(vb, pn);
                while (i != 0xff)
                {
                    if (allocId == synthVoice[i].baseSample)
                    {
                        num++;
                    }

                    i = VB_PRIO_LINK_NEXT(vb, i);
                }

                prioNode = VB_PRIO_SORT_NEXT(vb, pn);
            }

            if (num >= maxVoices)
                goto have_voice;
        }

    steal:
        {
            voice = -1;
            if (voiceFreeListRoot != 0xff && type_alloc == 0)
            {
                voice = voiceFreeListRoot;
            }
            else
            {
                if (priority < voicePrioSortedRoot)
                {
                    return -1;
                }

                prioNode = voicePrioSortedRoot;

                while (prioNode != 0xFFFF && priority >= prioNode && voice == -1)
                {
                    pn3 = prioNode;
                    for (i = VB_PRIO_HEAD(vb, pn3); i != 0xff; i = VB_PRIO_LINK_NEXT(vb, i))
                    {
                        if ((synthVoice[i].block == 0) && (!type_alloc || fxFlag == synthVoice[i].streamKind))
                        {
                            if ((VOICE_CFLAGS(i) & 2) == 0)
                            {
                                if (voice != -1)
                                {
                                    if (synthVoice[voice].priorityValue > synthVoice[i].priorityValue)
                                        voice = i;
                                }
                                else
                                {
                                    voice = i;
                                }
                            }
                        }
                    }
                    prioNode = VB_PRIO_SORT_NEXT(vb, pn3);
                }

                if (voice == -1)
                {
                    return 0xffffffff;
                }
            }

            if (AV_PRIO(voice) > priority)
            {
                goto ret_neg1;
            }
        }

    have_voice:
        if (voice == -1)
        {
            goto ret_neg1;
        }

        fl = (SynthVoiceListNode*)((u8*)vb + voice * 4);
        if (fl[944].user == 1)
        {
            sfv = (SynthVoiceListNode*)((u8*)fl + 3776);
            i = sfv->prev;

            if (i != 0xff)
            {
                vb->freeList[i].next = sfv->next;
            }
            else
            {
                voiceFreeListRoot = sfv->next;
            }

            i = sfv->next;
            if (i != 0xff)
            {
                vb->freeList[i].prev = sfv->prev;
            }

            if (voice == voiceFreeListTail)
            {
                voiceFreeListTail = sfv->prev;
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

ret_neg1:
    return -1;
}

/*
 * Release a voice slot: clear voice flags, unlink from id table,
 * decrement counter, and mark id slot as free (-1).
 */
void voiceFree(McmdVoiceState* voice)
{
    macMakeInactive(voice, 2);
    voiceRemovePriority(voice);
    voice->macroBase = NULL;
    voice->priorityGroup = 0;
    {
        u32 voiceId = voice->voiceHandle;
        u32 v = voiceId & 0xff;
        SynthVoiceListNode* slot = &voiceFreeListSlots[v];
        if (slot->user == 0)
        {
            slot->user = 1;
            if (voiceFreeListRoot != 0xff)
            {
                slot->next = 0xff;
                slot->prev = voiceFreeListTail;
                voiceFreeListSlots[voiceFreeListTail].next = v;
            }
            else
            {
                slot->next = 0xff;
                slot->prev = 0xff;
                voiceFreeListRoot = v;
            }
            voiceFreeListTail = v;
            if (voice->streamKind != 0)
            {
                voiceFxRunning--;
            }
            else
            {
                voiceMusicRunning--;
            }
        }
    }
    *(int*)&voice->voiceHandle = -1;
}
