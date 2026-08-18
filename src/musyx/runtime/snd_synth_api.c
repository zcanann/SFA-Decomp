#include "musyx/snd_synth_api.h"
#include "musyx/synth_voice.h"

#include "musyx/mcmd.h"
#include "musyx/sal_dsp.h"
#include "musyx/synth_delay.h"
#include "musyx/synth_volume.h"
#include "musyx/voice_id.h"
#include "musyx/synth_jobs.h"
#include "musyx/hw_input.h"
#include "musyx/hw_init.h"
#include "musyx/hw_samplemem.h"
#include "musyx/hw_stream.h"
#include "musyx/hw_volume.h"
#include "musyx/synth_callback.h"
#include "musyx/voice_manage.h"
#include "musyx/synth_config.h"
#include "musyx/synth_handle.h"
#include "musyx/synth_queue.h"

#define SYNTH_VOICE_DIRTY_FLAGS_OFFSET        0x114

/* sndOutputMode() output configuration (MusyX SND_OUTPUTMODE) */
#define SND_OUTPUTMODE_MONO     0 /* mono downmix */
#define SND_OUTPUTMODE_STEREO   1 /* plain stereo */
#define SND_OUTPUTMODE_SURROUND 2 /* Dolby Pro Logic surround */


/*
 * MusyX sequence volume API, wrapping the underlying synth volume helper.
 */
void sndSeqVolume(u8 volume, u16 time, u32 seqId, u8 mode)
{
    sndBegin();
    seqVolume(volume, time, seqId, mode);
    sndEnd();
}

/*
 * Look up a sequence MIDI priority halfword from a 2D table.
 */
u16 seqGetMIDIPriority(u8 slot, u8 event)
{
    return seqMIDIPriority[slot][event];
}

/*
 * MusyX FX controller wrapper.
 */
int sndFXCtrl(u32 handle, u8 controller, u8 value)
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
int sndFXCtrl14(u32 handle, u8 controller, u16 value)
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
int sndFXKeyOff(u32 handle)
{
    int result;
    sndBegin();
    result = synthSendKeyOff(handle);
    sndEnd();
    return result;
}

u32 sndFXStartEx(u16 fxId, u8 volume, u8 pan, u8 studio)
{
    u32 result;
    u8 auxIndex;
    sndBegin();
    auxIndex = synthITDDefault[studio].sfx;
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
            *(u64*)&synthVoice[i].cFlagsHi |= 0x0000200000000000ULL;
        }
        streamOutputModeChanged();
    }
}

/*
 * Configure studio AUX A/B processing callbacks and cache the callback
 * routing indices used by synth voice updates.
 */
void sndSetAuxProcessingCallbacks(u8 studio, SynthAuxCallback auxACallback, void* auxAUser, u8 auxAIndex,
                                  void* auxAData, SynthAuxCallback auxBCallback, void* auxBUser, u8 auxBIndex,
                                  void* auxBData)
{
    sndBegin();
    if (auxACallback != 0)
    {
        synthAuxAMIDI[studio] = auxAIndex;
        if (auxAIndex != 0xff)
        {
            synthAuxAMIDISet[studio] = seqGetPrivateId((u32)auxAData);
            synthAuxACallback[studio] = auxACallback;
            synthAuxAUser[studio] = auxAUser;
        }
    }
    else
    {
        synthAuxACallback[studio] = 0;
        synthAuxAMIDI[studio] = 0xff;
    }
    if (auxBCallback != 0)
    {
        synthAuxBMIDI[studio] = auxBIndex;
        if (auxBIndex != 0xff)
        {
            synthAuxBMIDISet[studio] = seqGetPrivateId((u32)auxBData);
            synthAuxBCallback[studio] = auxBCallback;
            synthAuxBUser[studio] = auxBUser;
        }
    }
    else
    {
        synthAuxBCallback[studio] = 0;
        synthAuxBMIDI[studio] = 0xff;
    }
    hwSetAUXProcessingCallbacks(studio, auxACallback, auxAUser, auxBCallback, auxBUser);
    sndEnd();
}

/*
 * Reset a studio's tracking state (clear two ptr arrays + 0xFF in two
 * byte arrays + zero in a third) and call hwActivateStudio.
 */
void synthActivateStudio(u8 studio, u32 isMaster, SND_STUDIO_TYPE type)
{
    sndBegin();
    synthAuxACallback[studio] = 0;
    synthAuxBCallback[studio] = 0;
    synthAuxAMIDI[studio] = 0xff;
    synthAuxBMIDI[studio] = 0xff;
    synthITDDefault[studio].sfx = 0;
    synthITDDefault[studio].music = 0;
    hwActivateStudio(studio, isMaster, type);
    sndEnd();
}

/*
 * Deactivate a studio: clear routed AUX callbacks and release/off any voices
 * currently assigned to that studio.
 */
void synthDeactivateStudio(u8 studio)
{
    u32 offset;
    u32 i;
    u8* voice;

    i = 0;
    offset = 0;
    for (; i < SYNTH_CONFIGURATION->voiceCount; i++)
    {
        voice = (u8*)synthVoice + offset;
        if (studio == ((McmdVoiceState*)voice)->studio)
        {
            if (((McmdVoiceState*)voice)->id != 0xffffffff)
            {
                voiceKillSound(((McmdVoiceState*)voice)->vidList->vid);
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
    synthAuxACallback[studio] = 0;
    synthAuxBCallback[studio] = 0;
    synthAuxAMIDI[studio] = 0xff;
    synthAuxBMIDI[studio] = 0xff;
    sndEnd();
    hwDeactivateStudio(studio);
}

/*
 * Wrapper for hwAddInput.
 */
u32 synthAddStudioInput(u8 studio, SND_STUDIO_INPUT* input)
{
    return hwAddInput(studio, input);
}

/*
 * Wrapper for hwRemoveInput.
 */
u32 synthRemoveStudioInput(u8 studio, SND_STUDIO_INPUT* input)
{
    return hwRemoveInput(studio, input);
}
