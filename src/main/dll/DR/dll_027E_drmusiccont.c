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
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/render_envfx_api.h"
#include "main/gamebit_ids.h"
#include "main/game_object.h"
#include "main/newclouds.h"
#include "main/sky_api.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"

#include "main/dll/DR/dll_027E_drmusiccont.h"
#include "main/object_render_legacy.h"

const f32 lbl_803E6BC8 = 1.0f;
const f32 gDrMusicControlCloudOverridePosX = -15350.0f;
const f32 gDrMusicControlCloudOverridePosY = -1550.0f;
const f32 gDrMusicControlCloudOverridePosZ = 10875.0f;
const f32 lbl_803E6BD8 = 0.0f;
const f32 gDrMusicControlStingerTimerDuration = 60.0f;
const f32 gDrMusicControlRestartPointX = -15697.0f;
const f32 gDrMusicControlRestartPointY = -1501.0f;
const f32 gDrMusicControlRestartPointZ = 12928.0f;
const f32 lbl_803E6BEC = 0.0f;

#define DRMUSICCONT_ENVFX_A 0x210
#define DRMUSICCONT_ENVFX_B 0x20f
#define DRMUSICCONT_ENVFX_C 0x212
#define DRMUSICCONT_ENVFX_D 0x1ea

int drmusiccont_getExtraSize(void)
{
    return 4;
}

int drmusiccont_getObjectTypeId(void)
{
    return 0;
}

void drmusiccont_free(int obj)
{
    cloudClearOverridePosition();
}

void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6BC8);
    }
}

void drmusiccont_hitDetect(void)
{
}

void drmusiccont_update(GameObject* obj)
{
    DrmusiccontState* state = obj->extra;
    DrMusicContFlags* flags = &state->flags;
    u8 bitE30;
    u8 bitE31;
    u8 bitE32;
    u8 bitE33;
    u8 bitE38;
    u8 bitE3C;
    u8 bitE3D;
    u8 bitE3E;
    u8 bit9E0;
    u8 bit9E1;
    u8 bit9E2;
    u8 bit9E7;

    cloudSetOverridePosition(gDrMusicControlCloudOverridePosX, gDrMusicControlCloudOverridePosY,
                             gDrMusicControlCloudOverridePosZ);
    if ((obj)->unkF4 == 0)
    {
        if ((u32)mainGetBit(GAMEBIT_DRArwingRelated0E7B) == 0)
        {
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, DRMUSICCONT_ENVFX_A, 0);
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, DRMUSICCONT_ENVFX_B, 0);
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, DRMUSICCONT_ENVFX_C, 0);
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, DRMUSICCONT_ENVFX_D, 0);
            skyFn_80088e54(0, lbl_803E6BD8);
            mainSetBits(GAMEBIT_DRArwingRelated0E7B, 1);
        }
        (obj)->unkF4 = 1;
    }

    SCGameBitLatch_Update(&state->gameBitLatch, 2, 0x1a7, 0x64b, 0xf0e, 0xe5);
    SCGameBitLatch_UpdateInverted(&state->gameBitLatch, 1, -1, -1, 0xe26, 0xb8);
    SCGameBitLatch_Update(&state->gameBitLatch, 4, -1, -1, 0xcbb, 0xc4);

    bitE30 = (u8)mainGetBit(0xe30);
    bitE31 = (u8)mainGetBit(0xe31);
    bitE32 = (u8)mainGetBit(0xe32);
    bitE33 = (u8)mainGetBit(0xe33);
    if (flags->b_e9c == 0 && bitE30 && bitE31 && bitE32 && bitE33)
    {
        flags->b_e9c = 1;
        mainSetBits(GAMEBIT_DR_ShutDownRobotShields, 1);
        Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
    }
    else if (bitE30 != flags->b_e30 || bitE31 != flags->b_e31 || bitE32 != flags->b_e32 || bitE33 != flags->b_e33)
    {
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }
    flags->b_e30 = bitE30;
    flags->b_e31 = bitE31;
    flags->b_e32 = bitE32;
    flags->b_e33 = bitE33;

    bitE38 = (u8)mainGetBit(0xe38);
    bitE3C = (u8)mainGetBit(0xe3c);
    bitE3D = (u8)mainGetBit(0xe3d);
    bitE3E = (u8)mainGetBit(0xe3e);
    if (flags->b_e39 == 0 && bitE38 && bitE3C && bitE3D && bitE3E)
    {
        flags->b_e39 = 1;
        Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
    }
    else if (bitE38 != flags->b_e38 || bitE3C != flags->b_e3c || bitE3D != flags->b_e3d || bitE3E != flags->b_e3e)
    {
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }
    flags->b_e38 = bitE38;
    flags->b_e3c = bitE3C;
    flags->b_e3d = bitE3D;
    flags->b_e3e = bitE3E;

    bit9E0 = (u8)mainGetBit(0x9e0);
    bit9E1 = (u8)mainGetBit(0x9e1);
    bit9E2 = (u8)mainGetBit(0x9e2);
    bit9E7 = (u8)mainGetBit(0x9e7);
    if (!(bit9E0 && bit9E1 && bit9E2 && bit9E7))
    {
        if (bit9E0 != flags->b_9e0 || bit9E1 != flags->b_9e1 || bit9E2 != flags->b_9e2 || bit9E7 != flags->b_9e7)
        {
            state->stingerTimer = gDrMusicControlStingerTimerDuration;
        }
    }
    {
        f32 st = state->stingerTimer;
        f32 zero = lbl_803E6BD8;
        if (st > zero)
        {
            state->stingerTimer = st - timeDelta;
            if (state->stingerTimer <= zero)
            {
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_4bd);
            }
        }
    }
    flags->b_9e0 = bit9E0;
    flags->b_9e1 = bit9E1;
    flags->b_9e2 = bit9E2;
    flags->b_9e7 = bit9E7;

    if (flags->b_state != 0)
    {
        if ((u32)mainGetBit(0x9f0) == 0 || mainGetBit(GAMEBIT_DR_RescuedHighTop) != 0)
        {
            (*gMapEventInterface)->clearRestartPoint();
            flags->b_state = 0;
        }
    }
    else
    {
        if ((u32)mainGetBit(0x9f0) != 0 && mainGetBit(GAMEBIT_DR_RescuedHighTop) == 0)
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

ObjectDescriptor gDrMusicContObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)drmusiccont_initialise,
    (ObjectDescriptorCallback)drmusiccont_release,
    0,
    (ObjectDescriptorCallback)drmusiccont_init,
    (ObjectDescriptorCallback)drmusiccont_update,
    (ObjectDescriptorCallback)drmusiccont_hitDetect,
    (ObjectDescriptorCallback)drmusiccont_render,
    (ObjectDescriptorCallback)drmusiccont_free,
    (ObjectDescriptorCallback)drmusiccont_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)drmusiccont_getExtraSize,
};

void drmusiccont_init(GameObject* obj)
{
    DrmusiccontState* state = obj->extra;
    DrMusicContFlags* flags = &state->flags;

    flags->b_e30 = mainGetBit(0xe30);
    flags->b_e31 = mainGetBit(0xe31);
    flags->b_e32 = mainGetBit(0xe32);
    flags->b_e33 = mainGetBit(0xe33);
    flags->b_e9c = mainGetBit(GAMEBIT_DR_ShutDownRobotShields);
    flags->b_e38 = mainGetBit(0xe38);
    flags->b_e3c = mainGetBit(0xe3c);
    flags->b_e3d = mainGetBit(0xe3d);
    flags->b_e3e = mainGetBit(0xe3e);
    flags->b_e39 = mainGetBit(0xe39);
    flags->b_9e0 = mainGetBit(0x9e0);
    flags->b_9e1 = mainGetBit(0x9e1);
    flags->b_9e2 = mainGetBit(0x9e2);
    flags->b_9e7 = mainGetBit(0x9e7);
}

void drmusiccont_release(void)
{
}

void drmusiccont_initialise(void)
{
}
