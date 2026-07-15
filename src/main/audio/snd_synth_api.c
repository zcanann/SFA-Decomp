#include "main/audio/snd_synth_api.h"
#include "main/audio/synth_voice.h"

#pragma exceptions on
#include "main/audio/mcmd.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/synth_delay.h"
#include "main/audio/synth_volume.h"
#include "main/audio/voice_id.h"
#include "main/audio/synth_jobs.h"
#include "main/audio/hw_input.h"
#include "main/audio/hw_init.h"
#include "main/audio/hw_samplemem.h"
#include "main/audio/synth_callback.h"
#include "main/audio/voice_manage.h"
#include "main/audio/synth_config.h"

#define SYNTH_VOICE_DIRTY_FLAGS_OFFSET        0x114

/* sndOutputMode() output configuration (MusyX SND_OUTPUTMODE) */
#define SND_OUTPUTMODE_MONO     0 /* mono downmix */
#define SND_OUTPUTMODE_STEREO   1 /* plain stereo */
#define SND_OUTPUTMODE_SURROUND 2 /* Dolby Pro Logic surround */

extern u8 gSynthVoiceNotes[];
extern void* synthAuxAUser[8];
extern void* synthAuxACallback[8];
extern void* synthAuxBUser[8];
extern void* synthAuxBCallback[8];
extern u8 synthITDDefault[8][2];
extern u8 synthAuxBMIDISet[8];
extern u8 synthAuxBMIDI[8];
extern u8 synthAuxAMIDISet[8];
extern u8 synthAuxAMIDI[8];
extern u32 synthFlags;

extern void synthUpdateHandle(u32 value0, u32 value1, u32 handle, s32 mode);
extern void hwRemoveInput(u8 idx, void* input);
extern void hwActivateStudio(u8 slot, int a, int b);
extern void hwDeactivateStudio(u8 slot);
extern void hwSetAUXProcessingCallbacks(u32 studio, void* auxACallback, void* auxAUser, void* auxBCallback,
                                        void* auxBUser);
extern void hwOff(u32 slot);

/*
 * MusyX sequence volume API, wrapping the underlying synth volume helper.
 */
void sndSeqVolume(int seqId, int volume, int time, int mode)
{
    sndBegin();
    synthUpdateHandle(seqId, volume, time, mode);
    sndEnd();
}

/*
 * Look up a sequence MIDI priority halfword from a 2D table.
 */
u16 seqGetMIDIPriority(u8 slot, u8 event)
{
    return *(u16*)(gSynthVoiceNotes + slot * 32 + event * 2);
}

/*
 * MusyX FX controller wrapper.
 */
int sndFXCtrl(int handle, u8 controller, u8 value)
{
    int result;
    sndBegin();
    result = synthFXSetCtrl(handle, controller, value);
    sndEnd();
    return result;
}

/*
 * MusyX FX 14-bit controller wrapper.
 */
int sndFXCtrl14(int handle, u8 controller, u16 value)
{
    int result;
    sndBegin();
    result = synthFXSetCtrl14(handle, controller, value);
    sndEnd();
    return result;
}

/*
 * MusyX FX key-off wrapper. Rena's SFA-Amethyst export also names this
 * address audioStopSound, matching the game-facing behavior.
 */
int sndFXKeyOff(int handle)
{
    int result;
    sndBegin();
    result = synthSendKeyOff(handle);
    sndEnd();
    return result;
}

/*
 * MusyX FX start wrapper, adding the current studio's cached aux index.
 */
int sndFXStartEx(u32 fxId, u8 volume, u8 pan, u8 studio)
{
    int result;
    u8 auxIndex;
    sndBegin();
    auxIndex = synthITDDefault[studio][1];
    result = synthFXStart(fxId, volume, pan, studio, auxIndex);
    sndEnd();
    return result;
}

/*
 * Map id -> slot via vidGetInternalId, returns -1 sentinel if not found,
 * else returns the input id.
 */
int sndFXCheck(u32 id)
{
    u32 slot;
    slot = vidGetInternalId(id);
    if (slot != 0xffffffff)
    {
        return id;
    }
    return -1;
}

/*
 * MusyX sequence volume-group volume wrapper.
 */
void sndVolume(u8 volume, u16 time, u8 group)
{
    sndBegin();
    synthVolume(volume, time, group, 0, -1);
    sndEnd();
}

/*
 * MusyX master-volume wrapper. The two flags gate the 0x15 and 0x16
 * controller updates.
 */
void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag)
{
    sndBegin();
    if (musicFlag != 0)
    {
        synthVolume(volume, time, 0x15, 0, -1);
    }
    if (fxFlag != 0)
    {
        synthVolume(volume, time, 0x16, 0, -1);
    }
    sndEnd();
}

/*
 * MusyX output-mode setter. It toggles the HRTF/stereo bits in
 * synthFlags and marks all voices dirty when the output mask changes.
 */
void sndOutputMode(int mode)
{
    u32 oldFlags = synthFlags;
    switch (mode)
    {
    case SND_OUTPUTMODE_MONO:
        synthFlags = synthFlags | 0x1;
        synthFlags = synthFlags & ~0x2;
        hwDisableHRTF();
        break;
    case SND_OUTPUTMODE_STEREO:
        synthFlags = synthFlags & ~0x1;
        synthFlags = synthFlags & ~0x2;
        hwDisableHRTF();
        break;
    case SND_OUTPUTMODE_SURROUND:
        synthFlags = synthFlags & ~0x1;
        synthFlags = synthFlags | 0x2;
        hwDisableHRTF();
        break;
    }
    if (oldFlags != synthFlags)
    {
        u32 i;
        for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; ++i)
        {
            *(u64*)((u8*)synthVoice + i * SYNTH_VOICE_STRIDE + SYNTH_VOICE_DIRTY_FLAGS_OFFSET) |= 0x0000200000000000ULL;
        }
        streamOutputModeChanged();
    }
}

/*
 * Configure studio AUX A/B processing callbacks and cache the callback
 * routing indices used by synth voice updates.
 */
void sndSetAuxProcessingCallbacks(u32 studio, void* auxACallback, void* auxAUser, u8 auxAIndex, void* auxAData,
                                  void* auxBCallback, void* auxBUser, u8 auxBIndex, void* auxBData)
{
    sndBegin();
    if (auxACallback != 0)
    {
        synthAuxAMIDI[studio & 0xff] = auxAIndex;
        if (auxAIndex != 0xff)
        {
            synthAuxAMIDISet[studio & 0xff] = synthResolveHandle((u32)auxAData);
            synthAuxACallback[studio & 0xff] = auxACallback;
            synthAuxAUser[studio & 0xff] = auxAUser;
        }
    }
    else
    {
        synthAuxACallback[studio & 0xff] = 0;
        synthAuxAMIDI[studio & 0xff] = 0xff;
    }
    if (auxBCallback != 0)
    {
        synthAuxBMIDI[studio & 0xff] = auxBIndex;
        if (auxBIndex != 0xff)
        {
            synthAuxBMIDISet[studio & 0xff] = synthResolveHandle((u32)auxBData);
            synthAuxBCallback[studio & 0xff] = auxBCallback;
            synthAuxBUser[studio & 0xff] = auxBUser;
        }
    }
    else
    {
        synthAuxBCallback[studio & 0xff] = 0;
        synthAuxBMIDI[studio & 0xff] = 0xff;
    }
    hwSetAUXProcessingCallbacks(studio, auxACallback, auxAUser, auxBCallback, auxBUser);
    sndEnd();
}

/*
 * Reset a slot's tracking state (clear two ptr arrays + 0xFF in two
 * byte arrays + zero in a third) and call hwActivateStudio.
 */
void synthActivateStudio(u8 slot, int a, int b)
{
    sndBegin();
    synthAuxACallback[slot] = 0;
    synthAuxBCallback[slot] = 0;
    synthAuxAMIDI[slot] = 0xff;
    synthAuxBMIDI[slot] = 0xff;
    synthITDDefault[slot][1] = 0;
    synthITDDefault[slot][0] = 0;
    hwActivateStudio(slot, a, b);
    sndEnd();
}

/*
 * Deactivate a studio: clear routed AUX callbacks and release/off any voices
 * currently assigned to that studio.
 */
void synthDeactivateStudio(u8 slot)
{
    u32 offset;
    u32 i;
    u8* voice;

    i = 0;
    offset = 0;
    for (; i < SYNTH_CONFIGURATION->voiceCount; i++)
    {
        voice = (u8*)synthVoice + offset;
        if (slot == ((McmdVoiceState*)voice)->studio)
        {
            if (((McmdVoiceState*)voice)->voiceHandle != 0xffffffff)
            {
                voiceKillById(((McmdVoiceState*)voice)->vidListNode->id);
            }
            else
            {
                if (hwIsActive(i) != 0)
                {
                    hwOff(i);
                }
            }
        }
        offset += SYNTH_VOICE_STRIDE;
    }
    sndBegin();
    synthAuxACallback[slot] = 0;
    synthAuxBCallback[slot] = 0;
    synthAuxAMIDI[slot] = 0xff;
    synthAuxBMIDI[slot] = 0xff;
    sndEnd();
    hwDeactivateStudio(slot);
}

/*
 * Wrapper for hwAddInput.
 */
void synthAddStudioInput(u8 idx, void* input)
{
    hwAddInput(idx, input);
}

/*
 * Wrapper for hwRemoveInput.
 */
void synthRemoveStudioInput(u8 idx, void* input)
{
    hwRemoveInput(idx, input);
}
