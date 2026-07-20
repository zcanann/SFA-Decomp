#include "main/audio/hw_volume.h"
#include "main/audio/dsp_voice_state.h"
#include "main/audio/hw_dspctrl.h"
#include "main/audio/sal_studio.h"
#include "main/audio/sal_volume.h"


extern DSPstudioinfo dspStudio[8];
extern u8 lbl_802C2820[];
extern f32 lbl_803E78E4;

/*
 * hwSetVolume - large mix-volume setter; computes 4-channel pan from
 * 3-axis float input via salCalcVolumeMatrix, clamps each to s16, and writes
 * back to the voice's pan/volume table.
 */
void hwSetVolume(u32 voiceIndex, u8 volumeTable, f32 volume, u32 pan, u32 surroundPan,
                 f32 auxA, f32 auxB)
{
    f32 out[9];
    u16 il;
    u16 ir;
    u16 is;
    DSPvoice* voice = (DSPvoice*)((u8*)dspVoice + voiceIndex * 0xf4);

    if (volume >= 1.0f)
        volume = 1.0f;
    if (auxA >= 1.0f)
        auxA = 1.0f;
    if (auxB >= 1.0f)
        auxB = 1.0f;

    {
        u32 f0w = voice->flags;
        f0w &= 0x80000000;
        salCalcVolumeMatrix(volumeTable, out, pan, surroundPan, f0w != 0,
                            dspStudio[voice->studio].type == 1, volume, auxA, auxB);
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
        u8* p = lbl_802C2820 + (((pan >> 16) & 0xff) << 1);
        voice->itdShiftL = *(u16*)p;
        voice->itdShiftR = 0x20 - *(u16*)p;
        voice->changed[0] |= 0x200;
    }
}

/*
 * Disable a voice slot.
 */
void hwOff(s32 slot)
{
    salDeactivateVoice(&dspVoice[slot]);
}

/*
 * Set the four AUX-mix DSP processing callbacks for a studio.
 */
void hwSetAUXProcessingCallbacks(u8 studio, SynthAuxCallback cb0, void* cb1, SynthAuxCallback cb2, void* cb3)
{
    DSPstudioinfo* entry = &dspStudio[studio];
    entry->auxAHandler = cb0;
    entry->auxAUser = cb1;
    entry->auxBHandler = cb2;
    entry->auxBUser = cb3;
}

/*
 * Activate the audio "studio" effect chain - thin wrapper.
 */
void hwActivateStudio(u8 studio, bool isMaster, SND_STUDIO_TYPE type)
{
    salActivateStudio(studio, isMaster, type);
}

/*
 * Deactivate the audio "studio" effect chain - thin wrapper.
 */
void hwDeactivateStudio(u8 studio)
{
    salDeactivateStudio(studio);
}
