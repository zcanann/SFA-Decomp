#include "ghidra_import.h"
#include "main/audio/snd_synth_api.h"

extern void sndBegin(void);
extern void sndEnd(void);
extern void synthUpdateHandle(u32 value0, u32 value1, u32 handle, s32 mode);
extern u32 synthSetHandleControllerValue(u32 handle, u8 controller, u8 value);
extern u32 synthSetHandleControllerValue14Bit(u32 handle, u8 controller, u16 value);
extern u32 synthHandleKeyOff(u32 handle);
extern int synthFXStart(u32 fxId, u8 volume, u8 pan, u8 studio, u8 studioAux);
extern void audioSetChannelVolume(u8 volume, u16 timeMs, u8 target, u8 action, u32 handle);
extern int vidGetInternalId(u32 id);
extern void synthRefreshJobVolumes(void);
extern void hwAddInput(u8 idx);
extern void hwRemoveInput(u8 idx);
extern void hwActivateStudio(u8 slot, int a, int b);
extern void hwDeactivateStudio(u8 slot);
extern void hwSetAUXProcessingCallbacks(u32 studio, void *auxACallback, void *auxAUser,
                                        void *auxBCallback, void *auxBUser);
extern u32 hwIsActive(u32 slot);
extern void hwOff(u32 slot);
extern void hwDisableHRTF(void);
extern u32 synthResolveHandle(u32 handle);
extern void voiceKillById(u32 value);

extern u8 lbl_803BCC90[];
extern u8 lbl_803BD150[];
extern void *lbl_803BD9A4[8];
extern void *lbl_803BD9C4[8];
extern void *lbl_803BD9E4[8];
extern void *lbl_803BDA04[8];
extern u8 lbl_803BDA24[8][2];
extern u8 synthAuxBMIDI[8];
extern u8 synthAuxBIndex[8];
extern u8 synthAuxAMIDI[8];
extern u8 synthAuxAIndex[8];
extern u32 synthFlags;
extern u8 *synthVoice;

/*
 * MusyX sequence volume API, wrapping the underlying synth volume helper.
 *
 * EN v1.1 Address: 0x80272720, size 100b
 */
void sndSeqVolume(int seqId, int volume, int time, int mode)
{
    sndBegin();
    synthUpdateHandle(seqId, volume, time, mode);
    sndEnd();
}

/*
 * Look up a sequence MIDI priority halfword from a 2D table.
 *
 * EN v1.1 Address: 0x80272788, size 32b
 */
u16 seqGetMIDIPriority(u8 slot, u8 event)
{
    return *(u16 *)(lbl_803BCC90 + slot * 32 + event * 2);
}

/*
 * MusyX FX controller wrapper.
 *
 * EN v1.1 Address: 0x802727A8, size 96b
 */
int sndFXCtrl(int handle, u8 controller, u8 value)
{
    int result;
    sndBegin();
    result = synthSetHandleControllerValue(handle, controller, value);
    sndEnd();
    return result;
}

/*
 * MusyX FX 14-bit controller wrapper.
 *
 * EN v1.1 Address: 0x80272808, size 96b
 */
int sndFXCtrl14(int handle, u8 controller, u16 value)
{
    int result;
    sndBegin();
    result = synthSetHandleControllerValue14Bit(handle, controller, value);
    sndEnd();
    return result;
}

/*
 * MusyX FX key-off wrapper. Rena's SFA-Amethyst export also names this
 * address audioStopSound, matching the game-facing behavior.
 *
 * EN v1.1 Address: 0x80272868, size 64b
 */
int sndFXKeyOff(int handle)
{
    int result;
    sndBegin();
    result = synthHandleKeyOff(handle);
    sndEnd();
    return result;
}

/*
 * MusyX FX start wrapper, adding the current studio's cached aux index.
 *
 * EN v1.1 Address: 0x802728A8, size 132b
 */
int sndFXStartEx(u32 fxId, u8 volume, u8 pan, u8 studio)
{
    int result;
    u8 auxIndex;
    sndBegin();
    auxIndex = lbl_803BDA24[studio][1];
    result = synthFXStart(fxId, volume, pan, studio, auxIndex);
    sndEnd();
    return result;
}

/*
 * Map id -> slot via vidGetInternalId, returns -1 sentinel if not found,
 * else returns the input id.
 *
 * EN v1.1 Address: 0x8027292C, size 68b
 */
int sndFXCheck(u32 id)
{
    u32 slot;
    slot = vidGetInternalId(id);
    if (slot != 0xffffffff) {
        return (int)id;
    }
    return -1;
}

/*
 * MusyX sequence volume-group volume wrapper.
 *
 * EN v1.1 Address: 0x80272970, size 96b
 */
void sndVolume(u8 volume, u16 time, u8 group)
{
    sndBegin();
    audioSetChannelVolume(volume, time, group, 0, -1);
    sndEnd();
}

/*
 * MusyX master-volume wrapper. The two flags gate the 0x15 and 0x16
 * controller updates.
 *
 * EN v1.1 Address: 0x802729D0, size 148b
 */
void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag)
{
    sndBegin();
    if (musicFlag != 0) {
        audioSetChannelVolume(volume, time, 0x15, 0, -1);
    }
    if (fxFlag != 0) {
        audioSetChannelVolume(volume, time, 0x16, 0, -1);
    }
    sndEnd();
}

/*
 * MusyX output-mode setter. It toggles the HRTF/stereo bits in
 * synthFlags and marks all voices dirty when the output mask changes.
 *
 * EN v1.1 Address: 0x80272A64, size 248b
 */
void sndOutputMode(int mode)
{
    u32 oldFlags = synthFlags;
    switch (mode) {
    case 0:
        synthFlags = synthFlags | 0x1;
        synthFlags = synthFlags & ~0x2;
        hwDisableHRTF();
        break;
    case 1:
        synthFlags = synthFlags & ~0x1;
        synthFlags = synthFlags & ~0x2;
        hwDisableHRTF();
        break;
    case 2:
        synthFlags = synthFlags & ~0x1;
        synthFlags = synthFlags | 0x2;
        hwDisableHRTF();
        break;
    }
    if (oldFlags != synthFlags) {
        u32 i;
        for (i = 0; i < lbl_803BD150[0x210]; i++) {
            volatile u32 *flags = (volatile u32 *)(synthVoice + i * 0x404 + 0x114);
            u32 nextFlags = flags[1];
            flags[1] = nextFlags;
            flags[0] |= 0x2000;
        }
        synthRefreshJobVolumes();
    }
}

/*
 * Configure studio AUX A/B processing callbacks and cache the callback
 * routing indices used by synth voice updates.
 *
 * EN v1.1 Address: 0x80272B5C, size 360b
 */
void sndSetAuxProcessingCallbacks(u32 studio, void *auxACallback, void *auxAUser, u8 auxAIndex,
                                  void *auxAData, void *auxBCallback, void *auxBUser,
                                  u8 auxBIndex, void *auxBData)
{
    sndBegin();
    if (auxACallback != 0) {
        synthAuxAIndex[studio & 0xff] = auxAIndex;
        if (auxAIndex != 0xff) {
            synthAuxAMIDI[studio & 0xff] = synthResolveHandle((u32)auxAData);
            lbl_803BD9C4[studio & 0xff] = auxACallback;
            lbl_803BD9A4[studio & 0xff] = auxAUser;
        }
    } else {
        lbl_803BD9C4[studio & 0xff] = 0;
        synthAuxAIndex[studio & 0xff] = 0xff;
    }
    if (auxBCallback != 0) {
        synthAuxBIndex[studio & 0xff] = auxBIndex;
        if (auxBIndex != 0xff) {
            synthAuxBMIDI[studio & 0xff] = synthResolveHandle((u32)auxBData);
            lbl_803BDA04[studio & 0xff] = auxBCallback;
            lbl_803BD9E4[studio & 0xff] = auxBUser;
        }
    } else {
        lbl_803BDA04[studio & 0xff] = 0;
        synthAuxBIndex[studio & 0xff] = 0xff;
    }
    hwSetAUXProcessingCallbacks(studio, auxACallback, auxAUser, auxBCallback, auxBUser);
    sndEnd();
}

/*
 * Reset a slot's tracking state (clear two ptr arrays + 0xFF in two
 * byte arrays + zero in a third) and call hwActivateStudio.
 *
 * EN v1.1 Address: 0x80272CC4, size 176b
 */
void synthActivateStudio(u8 slot, int a, int b)
{
    sndBegin();
    lbl_803BD9C4[slot] = 0;
    lbl_803BDA04[slot] = 0;
    synthAuxAIndex[slot] = 0xff;
    synthAuxBIndex[slot] = 0xff;
    lbl_803BDA24[slot][1] = 0;
    lbl_803BDA24[slot][0] = 0;
    hwActivateStudio(slot, a, b);
    sndEnd();
}

/*
 * Deactivate a studio: clear routed AUX callbacks and release/off any voices
 * currently assigned to that studio.
 *
 * EN v1.1 Address: 0x80272D74, size 240b
 */
void synthDeactivateStudio(u8 slot)
{
    u32 i;
    u32 offset;
    u8 *voice;

    offset = 0;
    for (i = 0; i < lbl_803BD150[0x210]; i++) {
        voice = synthVoice + offset;
        if (slot == *(u8 *)(voice + 0x11f)) {
            if (*(u32 *)(voice + 0xf4) != 0xffffffff) {
                voiceKillById(*(u32 *)(*(u32 *)(voice + 0xf8) + 8));
            } else {
                if (hwIsActive(i) != 0) {
                    hwOff(i);
                }
            }
        }
        offset += 0x404;
    }
    sndBegin();
    lbl_803BD9C4[slot] = 0;
    lbl_803BDA04[slot] = 0;
    synthAuxAIndex[slot] = 0xff;
    synthAuxBIndex[slot] = 0xff;
    sndEnd();
    hwDeactivateStudio(slot);
}

/*
 * Wrapper for hwAddInput.
 *
 * EN v1.1 Address: 0x80272E64, size 32b
 */
void synthAddStudioInput(u8 idx)
{
    hwAddInput(idx);
}

/*
 * Wrapper for hwRemoveInput.
 *
 * EN v1.1 Address: 0x80272E84, size 32b
 */
void synthRemoveStudioInput(u8 idx)
{
    hwRemoveInput(idx);
}
