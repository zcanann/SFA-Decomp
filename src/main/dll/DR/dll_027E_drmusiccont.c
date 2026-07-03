/*
 * drmusiccont (DLL 0x27E) - an invisible music/ambience controller for
 * its map.
 *
 * update overrides the cloud position, runs a one-shot env-fx and sky
 * setup the first frame, and drives several game-bit latches
 * (SCGameBitLatch_*). It watches two quads of "switch" game bits and a
 * third quad: completing the first two quads sets a progress bit and
 * plays a stinger, any change within a quad plays a mutter cue, and a
 * change in the third quad arms a short countdown (unk4) that fires a
 * one-shot sfx on expiry. It also toggles a map restart point based on
 * two more game bits. State: a f32 countdown at 0x4 and the
 * DrMusicContFlags cache at 0x8.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct DrmusiccontState
{
    u8 pad0[0x4 - 0x0];
    f32 stingerTimer; /* 0x04 */
} DrmusiccontState;


int drmusiccont_getExtraSize(void) { return 4; }

int drmusiccont_getObjectTypeId(void) { return 0; }

void drmusiccont_free(int obj) { cloudClearOverridePosition(obj); }

void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6BC8);
    }
}

void drmusiccont_hitDetect(void)
{
}

void drmusiccont_release(void)
{
}

void drmusiccont_initialise(void)
{
}

void drmusiccont_init(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    DrMusicContFlags* flags = (DrMusicContFlags*)(state + 0x8);

    flags->b_e30 = GameBit_Get(0xe30);
    flags->b_e31 = GameBit_Get(0xe31);
    flags->b_e32 = GameBit_Get(0xe32);
    flags->b_e33 = GameBit_Get(0xe33);
    flags->b_e9c = GameBit_Get(0xe9c);
    flags->b_e38 = GameBit_Get(0xe38);
    flags->b_e3c = GameBit_Get(0xe3c);
    flags->b_e3d = GameBit_Get(0xe3d);
    flags->b_e3e = GameBit_Get(0xe3e);
    flags->b_e39 = GameBit_Get(0xe39);
    flags->b_9e0 = GameBit_Get(0x9e0);
    flags->b_9e1 = GameBit_Get(0x9e1);
    flags->b_9e2 = GameBit_Get(0x9e2);
    flags->b_9e7 = GameBit_Get(0x9e7);
}

void drmusiccont_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    DrMusicContFlags* flags = (DrMusicContFlags*)(state + 0x8);
    u32 bit0;
    u32 bit1;
    u32 bit2;
    u32 bit3;

    cloudSetOverridePosition(obj, gDrMusicControlCloudOverridePosX, gDrMusicControlCloudOverridePosY, gDrMusicControlCloudOverridePosZ);
    if (((GameObject*)obj)->unkF4 == 0)
    {
        if ((u32)GameBit_Get(0xe7b) == 0)
        {
            getEnvfxActImmediately(obj, obj, 0x210, 0);
            getEnvfxActImmediately(obj, obj, 0x20f, 0);
            getEnvfxActImmediately(obj, obj, 0x212, 0);
            getEnvfxActImmediately(obj, obj, 0x1ea, 0);
            skyFn_80088e54(0, lbl_803E6BD8);
            GameBit_Set(0xe7b, 1);
        }
        ((GameObject*)obj)->unkF4 = 1;
    }

    SCGameBitLatch_Update(state, 2, 0x1a7, 0x64b, 0xf0e, 0xe5);
    SCGameBitLatch_UpdateInverted(state, 1, -1, -1, 0xe26, 0xb8);
    SCGameBitLatch_Update(state, 4, -1, -1, 0xcbb, 0xc4);

    bit0 = (u8)GameBit_Get(0xe30);
    bit1 = (u8)GameBit_Get(0xe31);
    bit2 = (u8)GameBit_Get(0xe32);
    bit3 = (u8)GameBit_Get(0xe33);
    if (flags->b_e9c == 0 && bit0 && bit1 && bit2 && bit3)
    {
        flags->b_e9c = 1;
        GameBit_Set(0xe9c, 1);
        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
    }
    else if (bit0 != flags->b_e30 || bit1 != flags->b_e31 || bit2 != flags->b_e32 || bit3 != flags->b_e33)
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    flags->b_e30 = bit0;
    flags->b_e31 = bit1;
    flags->b_e32 = bit2;
    flags->b_e33 = bit3;

    bit0 = (u8)GameBit_Get(0xe38);
    bit1 = (u8)GameBit_Get(0xe3c);
    bit2 = (u8)GameBit_Get(0xe3d);
    bit3 = (u8)GameBit_Get(0xe3e);
    if (flags->b_e39 == 0 && bit0 && bit1 && bit2 && bit3)
    {
        flags->b_e39 = 1;
        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
    }
    else if (bit0 != flags->b_e38 || bit1 != flags->b_e3c || bit2 != flags->b_e3d || bit3 != flags->b_e3e)
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    flags->b_e38 = bit0;
    flags->b_e3c = bit1;
    flags->b_e3d = bit2;
    flags->b_e3e = bit3;

    bit0 = (u8)GameBit_Get(0x9e0);
    bit1 = (u8)GameBit_Get(0x9e1);
    bit2 = (u8)GameBit_Get(0x9e2);
    bit3 = (u8)GameBit_Get(0x9e7);
    if (!(bit0 && bit1 && bit2 && bit3))
    {
        if (bit0 != flags->b_9e0 || bit1 != flags->b_9e1 || bit2 != flags->b_9e2 || bit3 != flags->b_9e7)
        {
            ((DrmusiccontState*)state)->stingerTimer = gDrMusicControlStingerTimerDuration;
        }
    }
    {
        f32 st = ((DrmusiccontState*)state)->stingerTimer;
        f32 zero = lbl_803E6BD8;
        if (st > zero)
        {
            ((DrmusiccontState*)state)->stingerTimer = st - timeDelta;
            if (((DrmusiccontState*)state)->stingerTimer <= zero)
            {
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_4bd); /* sfx id */
            }
        }
    }
    flags->b_9e0 = bit0;
    flags->b_9e1 = bit1;
    flags->b_9e2 = bit2;
    flags->b_9e7 = bit3;

    if (flags->b_state != 0)
    {
        if ((u32)GameBit_Get(0x9f0) == 0 || GameBit_Get(0x632) != 0)
        {
            (*gMapEventInterface)->clearRestartPoint();
            flags->b_state = 0;
        }
    }
    else
    {
        if ((u32)GameBit_Get(0x9f0) != 0 && GameBit_Get(0x632) == 0)
        {
            f32 vec[3];
            vec[0] = gDrMusicControlRestartPointX;
            vec[1] = gDrMusicControlRestartPointY;
            vec[2] = gDrMusicControlRestartPointZ;
            (*gMapEventInterface)->restartPoint(vec, 0x7fff, 0, 0);
            flags->b_state = 1;
        }
    }
}
