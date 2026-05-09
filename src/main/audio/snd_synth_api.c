#include "ghidra_import.h"
#include "main/audio/snd_synth_api.h"

extern void sndBegin(void);
extern void sndEnd(void);
extern void fn_8026D6E4(u32 value0, u32 value1, u32 handle, u32 mode);
extern int fn_8027186C(int a, int b, int c);
extern int fn_80271954(int a, int b, int c);
extern int fn_80271AC0(int a);
extern int fn_802717B0(u32 fxId, u32 volume, u32 pan, u32 studio, u8 studioAux);
extern int fn_80271B4C(int a, int b, int c, int d, int e);
extern int vidGetInternalId(u32 id);
extern void fn_80273870(void);
extern void hwAddInput(u8 idx);
extern void hwRemoveInput(u8 idx);
extern void hwActivateStudio(int a, int b, int c);
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
extern u8 lbl_803BD9A4[];
extern u8 lbl_803BD9C4[];
extern u8 lbl_803BD9E4[];
extern u8 lbl_803BDA04[];
extern u8 lbl_803BDA24[];
extern u8 lbl_803DE23C;
extern u8 lbl_803DE244;
extern u8 lbl_803DE24C;
extern u8 lbl_803DE254;
extern u32 lbl_803DE264;
extern u8 *lbl_803DE268;

/*
 * MusyX sequence volume API, wrapping the underlying synth volume helper.
 *
 * EN v1.1 Address: 0x80272720, size 100b
 */
void sndSeqVolume(int seqId, int volume, int time, int mode)
{
    sndBegin();
    fn_8026D6E4(seqId, volume, time, mode);
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
int sndFXCtrl(int handle, int controller, int value)
{
    int result;
    sndBegin();
    result = fn_8027186C(handle, controller, value);
    sndEnd();
    return result;
}

/*
 * MusyX FX 14-bit controller wrapper.
 *
 * EN v1.1 Address: 0x80272808, size 96b
 */
int sndFXCtrl14(int handle, int controller, int value)
{
    int result;
    sndBegin();
    result = fn_80271954(handle, controller, value);
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
    result = fn_80271AC0(handle);
    sndEnd();
    return result;
}

/*
 * MusyX FX start wrapper, adding the current studio's cached aux index.
 *
 * EN v1.1 Address: 0x802728A8, size 132b
 */
int sndFXStartEx(int fxId, int volume, int pan, int studio)
{
    int result;
    u8 auxIndex;
    sndBegin();
    auxIndex = lbl_803BDA24[(u8)studio * 2 + 1];
    result = fn_802717B0(fxId, volume, pan, studio, auxIndex);
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
void sndVolume(int group, int volume, int time)
{
    sndBegin();
    fn_80271B4C(group, volume, time, 0, -1);
    sndEnd();
}

/*
 * MusyX master-volume wrapper. The two flags gate the 0x15 and 0x16
 * controller updates.
 *
 * EN v1.1 Address: 0x802729D0, size 148b
 */
void sndMasterVolume(int volume, int time, u8 musicFlag, u8 fxFlag)
{
    sndBegin();
    if (musicFlag != 0) {
        fn_80271B4C(volume, time, 0x15, 0, -1);
    }
    if (fxFlag != 0) {
        fn_80271B4C(volume, time, 0x16, 0, -1);
    }
    sndEnd();
}

/*
 * MusyX output-mode setter. It toggles the HRTF/stereo bits in
 * lbl_803DE264 and marks all voices dirty when the output mask changes.
 *
 * EN v1.1 Address: 0x80272A64, size 248b
 */
void sndOutputMode(int mode)
{
    u32 oldFlags = lbl_803DE264;
    switch (mode) {
    case 0:
        lbl_803DE264 = lbl_803DE264 | 0x1;
        lbl_803DE264 = lbl_803DE264 & ~0x2;
        hwDisableHRTF();
        break;
    case 1:
        lbl_803DE264 = lbl_803DE264 & ~0x1;
        lbl_803DE264 = lbl_803DE264 & ~0x2;
        hwDisableHRTF();
        break;
    case 2:
        lbl_803DE264 = lbl_803DE264 & ~0x1;
        lbl_803DE264 = lbl_803DE264 | 0x2;
        hwDisableHRTF();
        break;
    }
    if (oldFlags != lbl_803DE264) {
        u32 i;
        for (i = 0; i < lbl_803BD150[0x210]; i++) {
            u32 *flags = (u32 *)(lbl_803DE268 + i * 0x404 + 0x114);
            u32 nextFlags = flags[1];
            flags[0] |= 0x2000;
            flags[1] = nextFlags;
        }
        fn_80273870();
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
        (&lbl_803DE254)[studio & 0xff] = auxAIndex;
        if (auxAIndex != 0xff) {
            (&lbl_803DE24C)[studio & 0xff] = synthResolveHandle((u32)auxAData);
            *(u32 *)(lbl_803BD9C4 + (studio & 0xff) * 4) = (u32)auxACallback;
            *(u32 *)(lbl_803BD9A4 + (studio & 0xff) * 4) = (u32)auxAUser;
        }
    } else {
        *(u32 *)(lbl_803BD9C4 + (studio & 0xff) * 4) = 0;
        (&lbl_803DE254)[studio & 0xff] = 0xff;
    }
    if (auxBCallback != 0) {
        (&lbl_803DE244)[studio & 0xff] = auxBIndex;
        if (auxBIndex != 0xff) {
            (&lbl_803DE23C)[studio & 0xff] = synthResolveHandle((u32)auxBData);
            *(u32 *)(lbl_803BDA04 + (studio & 0xff) * 4) = (u32)auxBCallback;
            *(u32 *)(lbl_803BD9E4 + (studio & 0xff) * 4) = (u32)auxBUser;
        }
    } else {
        *(u32 *)(lbl_803BDA04 + (studio & 0xff) * 4) = 0;
        (&lbl_803DE244)[studio & 0xff] = 0xff;
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
void synthActivateStudio(u32 slot, int a, int b)
{
    sndBegin();
    *(u32 *)(lbl_803BD9C4 + slot * 4) = 0;
    *(u32 *)(lbl_803BDA04 + slot * 4) = 0;
    (&lbl_803DE254)[slot] = 0xff;
    (&lbl_803DE244)[slot] = 0xff;
    *(u8 *)(lbl_803BDA24 + slot * 2 + 1) = 0;
    *(u8 *)(lbl_803BDA24 + slot * 2) = 0;
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
        voice = lbl_803DE268 + offset;
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
    *(u32 *)(lbl_803BD9C4 + slot * 4) = 0;
    *(u32 *)(lbl_803BDA04 + slot * 4) = 0;
    (&lbl_803DE254)[slot] = 0xff;
    (&lbl_803DE244)[slot] = 0xff;
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
