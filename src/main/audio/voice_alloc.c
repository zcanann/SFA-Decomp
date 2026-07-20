#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/voice_manage.h"
#include "main/audio/mcmd_exec.h"
#include "main/audio/vidlisttables.h"
#include "main/audio/synth_config.h"
#include "main/audio/voice_alloc.h"
#include "main/audio/voice_id.h"
#include "main/audio/vid_init.h"
#include "main/audio/snd_core.h"


#define VOICE_CFLAGS(i) (*(u64*)&synthVoice[i].inputFlags)

#define VB_PRIO_HEAD(vb, p)      (*(u8*)((u8*)&(vb)->priorityGroupHeads[0] + (p)))
#define VB_PRIO_LINK_NEXT(vb, i) (((SynthVoiceListNode*)((u8*)&(vb)->priorityLinks[0] + (i) * 4))->next)
#define VB_PRIO_SORT_NEXT(vb, p) (((SynthRootListNode*)((u8*)&(vb)->prioritySortLinks[0] + (p) * 4))->next)
#define VOICE_PRIORITY_NONE      0xFFFF

SynthVoiceListNode voiceFreeListSlots[64];
/*
 * Allocate a voice id, preferring a free slot but stealing the lowest-priority
 * compatible active voice when limits are exceeded. (musyx synthvoice.c
 * voiceAllocate, pre-2.0.1 variant.)
 */
u32 voiceAllocate(u8 priority, u8 maxInstances, u16 allocId, u8 streamKind)
{
    u32 configuredVoiceLimit;
    s32 i;
    s32 allocationCount;
    s32 selectedVoice;
    u16 priorityGroup;
    u32 restrictToStreamKind;
    u32 scannedGroup;
    SynthVoiceListNode* freeSlot;
    SynthVoiceListNode* slotBase;
    VidListTables* voiceLists = (VidListTables*)vidListNodes;

    if (!synthIdleWaitActive)
    {
        if (streamKind)
        {
            restrictToStreamKind = (voiceFxRunning >= SYNTH_CONFIGURATION->fxVoiceCount &&
                                    SYNTH_CONFIGURATION->voiceCount > SYNTH_CONFIGURATION->fxVoiceCount);

            configuredVoiceLimit = SYNTH_CONFIGURATION->fxVoiceCount;
        }
        else
        {
            restrictToStreamKind = (voiceMusicRunning >= SYNTH_CONFIGURATION->musicVoiceCount &&
                                    SYNTH_CONFIGURATION->voiceCount > SYNTH_CONFIGURATION->musicVoiceCount);

            configuredVoiceLimit = SYNTH_CONFIGURATION->musicVoiceCount;
        }

        allocationCount = -1;
        if (configuredVoiceLimit > maxInstances)
        {
            allocationCount = 0;
            selectedVoice = -1;

            priorityGroup = voicePrioSortedRoot;
            while (priorityGroup != VOICE_PRIORITY_NONE && priority >= priorityGroup && selectedVoice == -1)
            {
                u32 group = priorityGroup;
                for (i = VB_PRIO_HEAD(voiceLists, group); i != SYNTH_INVALID_VOICE_U8;
                     i = VB_PRIO_LINK_NEXT(voiceLists, i))
                {
                    if (allocId != synthVoice[i].baseSample)
                        continue;
                    ++allocationCount;
                    if (synthVoice[i].block)
                        continue;

                    if (!restrictToStreamKind || streamKind == synthVoice[i].streamKind)
                    {
                        if (VOICE_CFLAGS(i) & 2)
                            continue;
                        if (selectedVoice != -1)
                        {
                            if (synthVoice[i].priorityValue < synthVoice[selectedVoice].priorityValue)
                                selectedVoice = i;
                        }
                        else
                            selectedVoice = i;
                    }
                }

                priorityGroup = VB_PRIO_SORT_NEXT(voiceLists, group);
            }

            if (allocationCount < maxInstances)
            {
                while (priorityGroup != VOICE_PRIORITY_NONE && allocationCount < maxInstances)
                {
                    u32 group = priorityGroup;
                    i = VB_PRIO_HEAD(voiceLists, group);
                    while (i != SYNTH_INVALID_VOICE_U8)
                    {
                        if (allocId == synthVoice[i].baseSample)
                        {
                            allocationCount++;
                        }

                        i = VB_PRIO_LINK_NEXT(voiceLists, i);
                    }

                    priorityGroup = VB_PRIO_SORT_NEXT(voiceLists, group);
                }
            }
        }

        if (allocationCount < maxInstances)
        {
            selectedVoice = -1;
            if (voiceFreeListRoot != SYNTH_INVALID_VOICE_U8 && restrictToStreamKind == 0)
            {
                selectedVoice = voiceFreeListRoot;
            }
            else
            {
                if (priority < voicePrioSortedRoot)
                {
                    return SYNTH_INVALID_VOICE;
                }

                priorityGroup = voicePrioSortedRoot;

                while (priorityGroup != VOICE_PRIORITY_NONE && priority >= priorityGroup && selectedVoice == -1)
                {
                    scannedGroup = priorityGroup;
                    for (i = VB_PRIO_HEAD(voiceLists, scannedGroup); i != SYNTH_INVALID_VOICE_U8;
                         i = VB_PRIO_LINK_NEXT(voiceLists, i))
                    {
                        if ((synthVoice[i].block == 0) &&
                            (!restrictToStreamKind || streamKind == synthVoice[i].streamKind))
                        {
                            if ((VOICE_CFLAGS(i) & 2) == 0)
                            {
                                if (selectedVoice != -1)
                                {
                                    if (synthVoice[selectedVoice].priorityValue > synthVoice[i].priorityValue)
                                        selectedVoice = i;
                                }
                                else
                                {
                                    selectedVoice = i;
                                }
                            }
                        }
                    }
                    priorityGroup = VB_PRIO_SORT_NEXT(voiceLists, scannedGroup);
                }

                if (selectedVoice == -1)
                {
                    return SYNTH_INVALID_VOICE;
                }
            }

            if (synthVoice[selectedVoice].priorityGroup > priority)
            {
                return SYNTH_INVALID_VOICE;
            }
        }

        if (selectedVoice == -1)
        {
            return SYNTH_INVALID_VOICE;
        }

        slotBase = (SynthVoiceListNode*)((u8*)voiceLists + selectedVoice * 4);
        if (slotBase[944].user == 1)
        {
            freeSlot = (SynthVoiceListNode*)((u8*)slotBase + 3776);
            i = freeSlot->prev;

            if (i != SYNTH_INVALID_VOICE_U8)
            {
                voiceLists->freeList[i].next = freeSlot->next;
            }
            else
            {
                voiceFreeListRoot = freeSlot->next;
            }

            i = freeSlot->next;
            if (i != SYNTH_INVALID_VOICE_U8)
            {
                voiceLists->freeList[i].prev = freeSlot->prev;
            }

            if (selectedVoice == voiceFreeListTail)
            {
                voiceFreeListTail = freeSlot->prev;
            }

            freeSlot->user = 0;
        }
        else if (synthVoice[selectedVoice].streamKind)
        {
            voiceFxRunning--;
        }
        else
        {
            voiceMusicRunning--;
        }
        if (streamKind != 0)
        {
            ++voiceFxRunning;
        }
        else
        {
            ++voiceMusicRunning;
        }
        return selectedVoice;
    }

    return SYNTH_INVALID_VOICE;
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
