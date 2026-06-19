#include "main/audio/hw_volume.h"
#include "main/audio/dsp_voice.h"

extern void salDeactivateVoice(void* entry);
extern void salActivateStudio(void);
extern void salDeactivateStudio(void);
extern u8* dspVoice;
extern u8 lbl_803CC1E0[];
extern u8 lbl_802C2820[];

extern f32 lbl_803E78E4;

/*
 * hwSetVolume - large mix-volume setter; computes 4-channel pan from
 * 3-axis float input via salCalcVolumeMatrix, clamps each to s16, and writes
 * back to the voice's pan/volume table.
 *
 * EN v1.0 Address: 0x8028383C
 * EN v1.0 Size: 720b (0x2D0)
 */
void hwSetVolume(int slot, u32 p2, f32 a, f32 b, f32 c, u32 aux, u32 p7)
{
    DSPvoice* voice;
    DSPstudioinfo* aux_entry;
    f32 out[9];
    int v0, v1, v2;

    voice = (DSPvoice*)(dspVoice + slot * 0xf4);

    if (a >= 1.0f) a = 1.0f;
    if (b >= 1.0f) b = 1.0f;
    if (c >= 1.0f) c = 1.0f;

    aux_entry = (DSPstudioinfo*)(lbl_803CC1E0 + voice->studio * 0xbc);

    {
        extern void salCalcVolumeMatrix(int voltab_index, f32* out, u32 pan, u32 span, u32 itd, u32 dpl2, f32 a, f32 b,
                                        f32 c);
        u32 f0w = voice->flags;
        salCalcVolumeMatrix(p2, out, aux, p7, (f0w & 0x80000000u) != 0,
                            aux_entry->type == 1, a, b, c);
    }

    v0 = (s32)(lbl_803E78E4 * out[0]);
    v1 = (s32)(lbl_803E78E4 * out[1]);
    v2 = (s32)(lbl_803E78E4 * out[2]);
    if (voice->lastUpdate.vol == 0xff
        || voice->volL != (u16)v0
        || voice->volR != (u16)v1
        || voice->volS != (u16)v2)
    {
        voice->volL = v0;
        voice->volR = v1;
        voice->volS = v2;
        voice->changed[0] |= 0x1;
        voice->lastUpdate.vol = 0;
    }

    v0 = (s32)(lbl_803E78E4 * out[3]);
    v1 = (s32)(lbl_803E78E4 * out[4]);
    v2 = (s32)(lbl_803E78E4 * out[5]);
    if (voice->lastUpdate.volA == 0xff
        || voice->volLa != (u16)v0
        || voice->volRa != (u16)v1
        || voice->volSa != (u16)v2)
    {
        voice->volLa = v0;
        voice->volRa = v1;
        voice->volSa = v2;
        voice->changed[0] |= 0x2;
        voice->lastUpdate.volA = 0;
    }

    v0 = (s32)(lbl_803E78E4 * out[6]);
    v1 = (s32)(lbl_803E78E4 * out[7]);
    v2 = (s32)(lbl_803E78E4 * out[8]);
    if (voice->lastUpdate.volB == 0xff
        || voice->volLb != (u16)v0
        || voice->volRb != (u16)v1
        || voice->volSb != (u16)v2)
    {
        voice->volLb = v0;
        voice->volRb = v1;
        voice->volSb = v2;
        voice->changed[0] |= 0x4;
        voice->lastUpdate.volB = 0;
    }

    if (voice->flags & 0x80000000)
    {
        u8* p = lbl_802C2820 + (((aux >> 16) & 0xff) << 1);
        voice->itdShiftL = *(u16*)p;
        voice->itdShiftR = 0x20 - *(u16*)p;
        voice->changed[0] |= 0x200;
    }
}

/*
 * Disable a voice slot.
 *
 * EN v1.0 Address: 0x80283AB0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80283B0C
 * EN v1.1 Size: 44b
 */
void hwOff(int slot)
{
    salDeactivateVoice(dspVoice + slot * 0xf4);
}

/*
 * Set the four AUX-mix DSP processing callbacks for a voice slot.
 *
 * EN v1.0 Address: 0x80283AB4
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80283B38
 * EN v1.1 Size: 40b
 */
void hwSetAUXProcessingCallbacks(u8 idx, void* cb0, void* cb1, void* cb2, void* cb3)
{
    DSPstudioinfo* entry = (DSPstudioinfo*)(lbl_803CC1E0 + idx * 0xbc);
    entry->auxAHandler = cb0;
    entry->auxAUser = cb1;
    entry->auxBHandler = cb2;
    entry->auxBUser = cb3;
}

/*
 * Activate the audio "studio" effect chain - thin wrapper.
 *
 * EN v1.1 Address: 0x80283B60
 * EN v1.1 Size: 32b
 */
void hwActivateStudio(void)
{
    salActivateStudio();
}

/*
 * Deactivate the audio "studio" effect chain - thin wrapper.
 *
 * EN v1.1 Address: 0x80283B80
 * EN v1.1 Size: 32b
 */
void hwDeactivateStudio(void)
{
    salDeactivateStudio();
}
