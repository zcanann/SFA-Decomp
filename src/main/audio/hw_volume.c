#include "main/audio/hw_volume.h"
#include "main/audio/dsp_voice.h"

#pragma exceptions on

extern u8* dspVoice;
extern u8 lbl_803CC1E0[];
extern u8 lbl_802C2820[];
extern f32 lbl_803E78E4;

extern void salDeactivateVoice(void* entry);
extern void salActivateStudio(void);
extern void salDeactivateStudio(void);
extern void salCalcVolumeMatrix(int voltab_index, f32* out, u32 pan, u32 span, u32 itd, u32 dpl2, f32 vol, f32 auxa,
                                f32 auxb);

/*
 * hwSetVolume - large mix-volume setter; computes 4-channel pan from
 * 3-axis float input via salCalcVolumeMatrix, clamps each to s16, and writes
 * back to the voice's pan/volume table.
 */
void hwSetVolume(int slot, u32 p2, f32 vol, f32 auxa, f32 auxb, u32 aux, u32 p7)
{
    f32 out[9];
    u16 il;
    u16 ir;
    u16 is;
    DSPvoice* voice = (DSPvoice*)(dspVoice + slot * 0xf4);

    if (vol >= 1.0f)
        vol = 1.0f;
    if (auxa >= 1.0f)
        auxa = 1.0f;
    if (auxb >= 1.0f)
        auxb = 1.0f;

    {
        u32 f0w = voice->flags;
        DSPstudioinfo* dspStudio = (DSPstudioinfo*)lbl_803CC1E0;
        f0w &= 0x80000000;
        salCalcVolumeMatrix(p2, out, aux, p7, f0w != 0, dspStudio[voice->studio].type == 1, vol, auxa, auxb);
    }

    il = lbl_803E78E4 * out[0];
    ir = lbl_803E78E4 * out[1];
    is = lbl_803E78E4 * out[2];
    if (voice->lastUpdate.vol == 0xff || voice->volL != il || voice->volR != ir || voice->volS != is)
    {
        voice->volL = il;
        voice->volR = ir;
        voice->volS = is;
        voice->changed[0] |= 0x1;
        voice->lastUpdate.vol = 0;
    }

    il = lbl_803E78E4 * out[3];
    ir = lbl_803E78E4 * out[4];
    is = lbl_803E78E4 * out[5];
    if (voice->lastUpdate.volA == 0xff || voice->volLa != il || voice->volRa != ir || voice->volSa != is)
    {
        voice->volLa = il;
        voice->volRa = ir;
        voice->volSa = is;
        voice->changed[0] |= 0x2;
        voice->lastUpdate.volA = 0;
    }

    il = lbl_803E78E4 * out[6];
    ir = lbl_803E78E4 * out[7];
    is = lbl_803E78E4 * out[8];
    if (voice->lastUpdate.volB == 0xff || voice->volLb != il || voice->volRb != ir || voice->volSb != is)
    {
        voice->volLb = il;
        voice->volRb = ir;
        voice->volSb = is;
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
 */
void hwOff(int slot)
{
    salDeactivateVoice(dspVoice + slot * 0xf4);
}

/*
 * Set the four AUX-mix DSP processing callbacks for a voice slot.
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
 */
void hwActivateStudio(void)
{
    salActivateStudio();
}

/*
 * Deactivate the audio "studio" effect chain - thin wrapper.
 */
void hwDeactivateStudio(void)
{
    salDeactivateStudio();
}
