#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80279EC0.h"

extern u32 hwIsActive(u32 voice);
extern void hwBreak(u32 voice);
extern void vidRemoveVoice(int handle);
extern void voiceFree(int handle);
extern u32 get_vidlist(u32 id);
extern void synthCancelJob(u8 voice);

extern u8 *synthVoice;
extern u8 lbl_803BD150[];
extern u8 gSynthInitialized;
extern u8 voicePriorityLinks[];
extern u8 voicePriorityGroupHeads[];
extern u8 voiceFreeListSlots[];
extern u8 voiceDirectSlots[];
extern u8 voiceMidiKeySlots[][16];
extern u16 voicePrioSortRootListRoot;
extern u8 voiceMusicRunning;
extern u8 voiceFxRunning;
extern u8 voiceListInsert;
extern u8 voiceListRoot;

/*
 * Initialize the voice priority and group linked-list tables.
 */
void voiceInitPriorityTables(void)
{
    s8 value;
    u8 lastVoice;
    int remaining;
    u8 *groupHead;
    u32 progress;
    u8 *activeSlot;
    s8 *freeSlot;
    u32 count;
    u32 batches;

    progress = 0;
    count = lbl_803BD150[0x210];
    if (count != 0) {
        if (count > 8) {
            batches = (count - 1) >> 3;
            freeSlot = (s8 *)voiceFreeListSlots;
            if (count != 8) {
                do {
                    value = progress;
                    freeSlot[0] = value - 1;
                    freeSlot[1] = value + 1;
                    *(u16 *)(freeSlot + 2) = 1;
                    freeSlot[4] = value;
                    freeSlot[5] = value + 2;
                    progress += 8;
                    *(u16 *)(freeSlot + 6) = 1;
                    freeSlot[8] = value + 1;
                    freeSlot[9] = value + 3;
                    *(u16 *)(freeSlot + 10) = 1;
                    freeSlot[12] = value + 2;
                    freeSlot[13] = value + 4;
                    *(u16 *)(freeSlot + 14) = 1;
                    freeSlot[16] = value + 3;
                    freeSlot[17] = value + 5;
                    *(u16 *)(freeSlot + 18) = 1;
                    freeSlot[20] = value + 4;
                    freeSlot[21] = value + 6;
                    *(u16 *)(freeSlot + 22) = 1;
                    freeSlot[24] = value + 5;
                    freeSlot[25] = value + 7;
                    *(u16 *)(freeSlot + 26) = 1;
                    freeSlot[28] = value + 6;
                    freeSlot[29] = value + 8;
                    *(u16 *)(freeSlot + 30) = 1;
                    freeSlot += 0x20;
                    batches--;
                } while (batches != 0);
            }
        }
        freeSlot = (s8 *)(voiceFreeListSlots + progress * 4);
        remaining = lbl_803BD150[0x210] - progress;
        if (progress < lbl_803BD150[0x210]) {
            do {
                value = progress;
                freeSlot[0] = value - 1;
                progress++;
                freeSlot[1] = value + 1;
                *(u16 *)(freeSlot + 2) = 1;
                freeSlot += 4;
                remaining--;
            } while (remaining != 0);
        }
    }

    lastVoice = lbl_803BD150[0x210];
    voiceFreeListSlots[0] = SYNTH_INVALID_VOICE_U8;
    progress = 0;
    count = lbl_803BD150[0x210];
    *(u8 *)(voiceFreeListSlots - 3 + count * 4) = SYNTH_INVALID_VOICE_U8;
    voiceListInsert = lastVoice - 1;
    voiceListRoot = 0;
    if (count != 0) {
        if (count > 8) {
            batches = (count - 1) >> 3;
            activeSlot = voicePriorityLinks;
            if (count != 8) {
                do {
                    *(u16 *)(activeSlot + 2) = 0;
                    progress += 8;
                    *(u16 *)(activeSlot + 6) = 0;
                    *(u16 *)(activeSlot + 10) = 0;
                    *(u16 *)(activeSlot + 14) = 0;
                    *(u16 *)(activeSlot + 18) = 0;
                    *(u16 *)(activeSlot + 22) = 0;
                    *(u16 *)(activeSlot + 26) = 0;
                    *(u16 *)(activeSlot + 30) = 0;
                    activeSlot += 0x20;
                    batches--;
                } while (batches != 0);
            }
        }
        activeSlot = voicePriorityLinks + progress * 4;
        remaining = lbl_803BD150[0x210] - progress;
        if (progress < lbl_803BD150[0x210]) {
            do {
                *(u16 *)(activeSlot + 2) = 0;
                activeSlot += 4;
                remaining--;
            } while (remaining != 0);
        }
    }

    remaining = 4;
    groupHead = voicePriorityGroupHeads;
    do {
        groupHead[0] = 0xff;
        groupHead[1] = 0xff;
        groupHead[2] = 0xff;
        groupHead[3] = 0xff;
        groupHead[4] = 0xff;
        groupHead[5] = 0xff;
        groupHead[6] = 0xff;
        groupHead[7] = 0xff;
        groupHead[8] = 0xff;
        groupHead[9] = 0xff;
        groupHead[10] = 0xff;
        groupHead[11] = 0xff;
        groupHead[12] = 0xff;
        groupHead[13] = 0xff;
        groupHead[14] = 0xff;
        groupHead[15] = 0xff;
        groupHead[16] = 0xff;
        groupHead[17] = 0xff;
        groupHead[18] = 0xff;
        groupHead[19] = 0xff;
        groupHead[20] = 0xff;
        groupHead[21] = 0xff;
        groupHead[22] = 0xff;
        groupHead[23] = 0xff;
        groupHead[24] = 0xff;
        groupHead[25] = 0xff;
        groupHead[26] = 0xff;
        groupHead[27] = 0xff;
        groupHead[28] = 0xff;
        groupHead[29] = 0xff;
        groupHead[30] = 0xff;
        groupHead[31] = 0xff;
        groupHead[32] = 0xff;
        groupHead[33] = 0xff;
        groupHead[34] = 0xff;
        groupHead[35] = 0xff;
        groupHead[36] = 0xff;
        groupHead[37] = 0xff;
        groupHead[38] = 0xff;
        groupHead[39] = 0xff;
        groupHead[40] = 0xff;
        groupHead[41] = 0xff;
        groupHead[42] = 0xff;
        groupHead[43] = 0xff;
        groupHead[44] = 0xff;
        groupHead[45] = 0xff;
        groupHead[46] = 0xff;
        groupHead[47] = 0xff;
        groupHead[48] = 0xff;
        groupHead[49] = 0xff;
        groupHead[50] = 0xff;
        groupHead[51] = 0xff;
        groupHead[52] = 0xff;
        groupHead[53] = 0xff;
        groupHead[54] = 0xff;
        groupHead[55] = 0xff;
        groupHead[56] = 0xff;
        groupHead[57] = 0xff;
        groupHead[58] = 0xff;
        groupHead[59] = 0xff;
        groupHead[60] = 0xff;
        groupHead[61] = 0xff;
        groupHead[62] = 0xff;
        groupHead[63] = 0xff;
        groupHead += 0x40;
        remaining--;
    } while (remaining != 0);
    voicePrioSortRootListRoot = 0xffff;
    voiceMusicRunning = 0;
    voiceFxRunning = 0;
}

/*
 * Voice cleanup: if voice handle is valid, break the active voice and
 * reset its id slot.
 *
 * EN v1.1 Address: 0x80279FAC, size 128b
 */
void voiceBreakAndFree(u32 voice)
{
    if (voice == SYNTH_INVALID_VOICE) return;
    if (hwIsActive(voice) != 0) {
        hwBreak(voice);
    }
    *(u32 *)(synthVoice + voice * SYNTH_VOICE_STRIDE + SYNTH_VOICE_HANDLE_OFFSET) = voice;
    voiceFree((int)(synthVoice + voice * SYNTH_VOICE_STRIDE));
    *(u8 *)(synthVoice + voice * SYNTH_VOICE_STRIDE + SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET) = 0;
}

/*
 * Voice teardown: clears state flags then breaks the voice.
 *
 * EN v1.1 Address: 0x8027A02C, size 160b
 */
void voiceKill(u32 voice)
{
    int base = (int)(synthVoice + voice * SYNTH_VOICE_STRIDE);
    if (*(u32 *)(base + SYNTH_VOICE_ACTIVE_HANDLE_OFFSET) != 0) {
        vidRemoveVoice(base);
        *(u32 *)(base + SYNTH_VOICE_STATE_FLAGS_OFFSET) =
            *(u32 *)(base + SYNTH_VOICE_STATE_FLAGS_OFFSET) & 0xFFFFFFFC;
        *(u32 *)(base + 0x114) = *(u32 *)(base + 0x114) & ~0;
        *(u32 *)(base + SYNTH_VOICE_PRIORITY_TICK_OFFSET) = 0;
        voiceFree(base);
    }
    if (*(u8 *)(base + SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET) != 0) {
        synthCancelJob((u8)voice);
    }
    hwBreak(voice);
}

/*
 * Walk the synth's voice list for the given id, breaking each match.
 * Returns 0 if at least one match was broken, else -1.
 *
 * EN v1.1 Address: 0x8027A0CC, size 272b
 */
int voiceKillById(u32 id)
{
    int result = -1;
    if (gSynthInitialized != 0) {
        u32 s;
        if ((id != SYNTH_INVALID_VOICE) && ((s = get_vidlist(id)) != 0)) {
            id = *(u32 *)(s + 0xc);
        } else {
            id = SYNTH_INVALID_VOICE;
        }

        while (id != SYNTH_INVALID_VOICE) {
            u8 v = (u8)id;
            int handle = (int)(synthVoice + v * SYNTH_VOICE_STRIDE);
            u32 chain = *(u32 *)(handle + SYNTH_VOICE_NEXT_HANDLE_OFFSET);
            if (id == *(u32 *)(handle + SYNTH_VOICE_HANDLE_OFFSET)) {
                if (*(u32 *)(handle + SYNTH_VOICE_ACTIVE_HANDLE_OFFSET) != 0) {
                    vidRemoveVoice(handle);
                    *(u32 *)(handle + SYNTH_VOICE_STATE_FLAGS_OFFSET) =
                        *(u32 *)(handle + SYNTH_VOICE_STATE_FLAGS_OFFSET) & 0xFFFFFFFC;
                    *(u32 *)(handle + 0x114) = *(u32 *)(handle + 0x114) & ~0;
                    *(u32 *)(handle + SYNTH_VOICE_PRIORITY_TICK_OFFSET) = 0;
                    voiceFree(handle);
                }
                if (*(u8 *)(handle + SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET) != 0) {
                    synthCancelJob(v);
                }
                hwBreak(v);
                result = 0;
            }
            id = chain;
        }
    }

    return result;
}

/*
 * Returns 1 if state's voice id is currently registered in the
 * appropriate slot table, else 0.
 *
 * EN v1.1 Address: 0x8027A1DC, size 124b
 */
int voiceIsRegistered(int state)
{
    u32 voice = *(u32 *)(state + SYNTH_VOICE_HANDLE_OFFSET);
    u8 a;
    u8 b;
    u8 v;
    if (voice == SYNTH_INVALID_VOICE) goto fail;
    a = *(u8 *)(state + SYNTH_VOICE_MIDI_SLOT_OFFSET);
    if (a == SYNTH_INVALID_VOICE_U8) goto fail;
    b = *(u8 *)(state + SYNTH_VOICE_MIDI_KEY_OFFSET);
    v = (u8)voice;
    if (b == SYNTH_INVALID_VOICE_U8) {
        if (voiceDirectSlots[v] == v) return 1;
        goto fail;
    }
    if (v == voiceMidiKeySlots[b][a]) return 1;
fail:
    return 0;
}

/*
 * Register the state's voice id in either the 1D or 2D slot table.
 *
 * EN v1.1 Address: 0x8027A258, size 92b
 */
void voiceRegister(int state)
{
    u32 voice = *(u32 *)(state + SYNTH_VOICE_HANDLE_OFFSET);
    u8 a;
    u8 b;
    u8 v;
    if (voice == SYNTH_INVALID_VOICE) return;
    a = *(u8 *)(state + SYNTH_VOICE_MIDI_SLOT_OFFSET);
    if (a == SYNTH_INVALID_VOICE_U8) return;
    b = *(u8 *)(state + SYNTH_VOICE_MIDI_KEY_OFFSET);
    v = (u8)voice;
    if (b == SYNTH_INVALID_VOICE_U8) {
        voiceDirectSlots[v] = v;
    } else {
        voiceMidiKeySlots[b][a] = v;
    }
}
