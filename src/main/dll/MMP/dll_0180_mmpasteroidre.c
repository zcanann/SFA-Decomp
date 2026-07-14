/*
 * mmpasteroidre (DLL 0x180) - Moon Mountain Pass asteroid re-entry object.
 *
 * A scripted falling asteroid. The sequence callback (mmp_asteroid_re_SeqFn)
 * consumes anim events to toggle lighting and drive phase transitions
 * (eventFlags / gamebit 0x87B). init seeds intensity (gamebit 0x88C) and
 * phase, restoring the right visual state on load. update integrates the
 * descent - gravity-like vertical motion toward a target height with a
 * sine wobble on position and rotation, looped re-entry sfx scaled by
 * intensity, and per-flag particle bursts (trails, sparks, the impact
 * explosion with camera shake + rumble). The state timer clears gamebit
 * 0x88B when it expires.
 */

#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/dll/MMP/mmp_asteroid_re_state.h"
#include "main/object_render_legacy.h"
#include "main/gamebit_ids.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/objanim_update.h"
#include "main/gamebits.h"
#include "main/lightmap_render_control_api.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/object_api.h"
#include "main/camera_shake_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/MMP/dll_0180_mmpasteroidre.h"
#include "main/object_descriptor.h"

STATIC_ASSERT(sizeof(MmpAsteroidReState) == 0x1C);

#define MMPASTEROIDRE_OBJFLAG_HIDDEN             0x4000
#define MMPASTEROIDRE_OBJFLAG_HITDETECT_DISABLED 0x2000

f32 gMmpAsteroidIntensityHeightTable[4] = {0.0f, 0.0f, 10.0f, 50.0f};
PartFxSpawnParams gMmpAsteroidDustSpawnParams;
extern int gMmpAsteroidDustHeightParam;
extern f32 lbl_803E44E8;
extern f32 lbl_803E44F8;
extern f32 lbl_803E44FC;
extern f32 lbl_803E4500;
extern f32 lbl_803E4504;
extern f32 lbl_803E4508;
extern f32 lbl_803E450C;
extern f32 lbl_803E4510;
extern f32 lbl_803E4514;
extern f32 lbl_803E4518;
extern f32 gMmpAsteroidPi;
extern f32 lbl_803E4520;
extern f32 lbl_803E4524;
extern f32 lbl_803E4528;
extern f32 lbl_803E452C;
extern f32 lbl_803E4530;
extern f32 lbl_803E4534;
extern f32 lbl_803E4538;
extern f32 lbl_803E453C;

void mmp_asteroid_re_free(void)
{
}

void mmp_asteroid_re_hitDetect(void)
{
}

void mmp_asteroid_re_release(void)
{
}

void mmp_asteroid_re_initialise(void)
{
}

int mmp_asteroid_re_getExtraSize(void)
{
    return 0x1c;
}
int mmp_asteroid_re_getObjectTypeId(void)
{
    return 0x0;
}

#pragma peephole off
void mmp_asteroid_re_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E44F8);
}

#pragma scheduling off
#pragma force_active on
__declspec(section ".sdata2") f32 lbl_803E44E8 = 3600.0f;
#pragma force_active reset

int mmp_asteroid_re_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{

    MmpAsteroidReState* state = (obj)->extra;
    int i;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 type = animUpdate->eventIds[i];
        switch (type)
        {
        case 0:
            setDrawLights(0);
            break;
        case 1:
            state->eventFlags = 13;
            state->phase = MMP_ASTEROID_PHASE_RISING;
            mainSetBits(GAMEBIT_MMPAsteroidRelated087B, state->phase);
            (obj)->anim.alpha = 0xff;
            break;
        case 2:
            state->eventFlags = state->eventFlags & ~9;
            state->eventFlags = state->eventFlags | 0x30;
            ((ObjAnimComponent*)obj)->bankIndex = 1;
            break;
        case 3:
        {
            int timer;
            state->eventFlags = state->eventFlags & ~ASTEROIDRE_FX_IMPACT;
            state->eventFlags = state->eventFlags | 0x50;
            timer = randomGetRange(10, 60);
            state->periodicFxTimer = timer;
            state->phase = MMP_ASTEROID_PHASE_RISING;
            mainSetBits(GAMEBIT_MMPAsteroidRelated087B, state->phase);
            break;
        }
        case 4:
            state->stateTimer = lbl_803E44E8;
            setDrawLights(1);
            break;
        }
    }
    state->eventFlags |= ASTEROIDRE_SEQ_TICK;
    mmp_asteroid_re_update((int)obj);
    return 0;
}

void mmp_asteroid_re_init(GameObject* obj)
{
    MmpAsteroidReState* state = obj->extra;
    obj->objectFlags |= (MMPASTEROIDRE_OBJFLAG_HIDDEN | MMPASTEROIDRE_OBJFLAG_HITDETECT_DISABLED);
    obj->animEventCallback = mmp_asteroid_re_SeqFn;
    state->eventFlags = 0;
    state->intensity = mainGetBit(0x88C);
    state->phase = mainGetBit(GAMEBIT_MMPAsteroidRelated087B);
    switch ((s32)state->phase)
    {
    case MMP_ASTEROID_PHASE_HIDDEN:
        obj->anim.alpha = 0;
        *(u8*)&obj->anim.bankIndex = 0;
        break;
    case MMP_ASTEROID_PHASE_RISING:
        obj->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&obj->anim.bankIndex = 1;
        state->eventFlags |= ASTEROIDRE_FX_PERIODIC;
        break;
    case MMP_ASTEROID_PHASE_RISEN:
        obj->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&obj->anim.bankIndex = 1;
        break;
    case MMP_ASTEROID_PHASE_RISEN_SAVED:
        obj->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&obj->anim.bankIndex = 1;
        break;
    }
    {
        f32 v = obj->anim.localPosY;
        state->baseY = v;
        state->baseY2 = v;
    }
}

#pragma force_active on
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E44F8 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E44FC = 0.5f;
__declspec(section ".sdata2") f32 lbl_803E4500 = 0.1f;
__declspec(section ".sdata2") f32 lbl_803E4504 = 0.03f;
__declspec(section ".sdata2") f32 lbl_803E4508 = 0.051f;
__declspec(section ".sdata2") f32 lbl_803E450C = 1024.0f;
__declspec(section ".sdata2") f32 lbl_803E4510 = 875.0f;
__declspec(section ".sdata2") f32 lbl_803E4514 = 512.0f;
__declspec(section ".sdata2") f32 lbl_803E4518 = 0.0f;
__declspec(section ".sdata2") f32 gMmpAsteroidPi = 3.14159274f;
__declspec(section ".sdata2") f32 lbl_803E4520 = 32768.0f;
__declspec(section ".sdata2") f32 lbl_803E4524 = 182.0f;
__declspec(section ".sdata2") f32 lbl_803E4528 = 55.0f;
__declspec(section ".sdata2") f32 lbl_803E452C = 100.0f;
__declspec(section ".sdata2") f32 lbl_803E4530 = 5.0f;
__declspec(section ".sdata2") f32 lbl_803E4534 = 10.0f;
__declspec(section ".sdata2") f32 lbl_803E4538 = 4.0f;
__declspec(section ".sdata2") f32 lbl_803E453C = 22.0f;
#pragma explicit_zero_data off
#pragma force_active reset

void mmp_asteroid_re_update(int obj)
{


    MmpAsteroidReState* state = ((GameObject*)obj)->extra;
    if ((state->eventFlags & ASTEROIDRE_SEQ_TICK) == 0)
    {
        if (mainGetBit(0xD52) != 0)
        {
            state->intensity = 1;
        }
        else
        {
            state->intensity = mainGetBit(0x88C);
        }
        state->phase = MMP_ASTEROID_PHASE_RISEN;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_lwfl1_c);
        {
            int vol = state->intensity * 0x20 + 0x20;
            if (vol > 0x7F)
            {
                vol = 0x7F;
            }
            Sfx_SetObjectChannelVolumeIntU8Legacy(obj, 0x40, vol, lbl_803E44FC);
        }
        if (state->intensity != 0)
        {
            f32 speed = ((GameObject*)obj)->anim.velocityY;
            if (speed < lbl_803E4500 * ((state->baseY + gMmpAsteroidIntensityHeightTable[state->intensity]) -
                                        ((GameObject*)obj)->anim.localPosY))
            {
                ((GameObject*)obj)->anim.velocityY = lbl_803E4504 * timeDelta + speed;
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY = -(lbl_803E4508 * timeDelta - speed);
            }
            *(s16*)&state->bobPhase = lbl_803E450C * timeDelta + state->bobPhase;
            *(s16*)&state->rollPhase = lbl_803E4510 * timeDelta + state->rollPhase;
            *(s16*)&state->pitchPhase = lbl_803E4514 * timeDelta + state->pitchPhase;
            ((void (*)(int, f32, f32, f32))objMove)(obj, lbl_803E4518, ((GameObject*)obj)->anim.velocityY * timeDelta,
                                                    *(f32*)&lbl_803E4518);
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.localPosY + mathSinf((gMmpAsteroidPi * state->bobPhase) / lbl_803E4520);
            if (((GameObject*)obj)->anim.localPosY < state->baseY)
            {
                ((GameObject*)obj)->anim.localPosY = state->baseY;
            }
            ((GameObject*)obj)->anim.rotZ =
                (s16)(((GameObject*)obj)->anim.rotZ +
                      (int)(lbl_803E4524 * mathSinf((gMmpAsteroidPi * state->rollPhase) / lbl_803E4520)));
            ((GameObject*)obj)->anim.rotY =
                (s16)(((GameObject*)obj)->anim.rotY +
                      (int)(lbl_803E4524 * mathSinf((gMmpAsteroidPi * state->pitchPhase) / lbl_803E4520)));
            gMmpAsteroidDustSpawnParams.scale = lbl_803E44F8;
            gMmpAsteroidDustSpawnParams.posX = ((GameObject*)obj)->anim.localPosX;
            gMmpAsteroidDustSpawnParams.posY = state->baseY - lbl_803E4528;
            gMmpAsteroidDustSpawnParams.posZ = ((GameObject*)obj)->anim.localPosZ;
            gMmpAsteroidDustHeightParam = (int)(((GameObject*)obj)->anim.localPosY - state->baseY);
            (*gPartfxInterface)
                ->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_DUST, NULL, 2, -1, &gMmpAsteroidDustHeightParam);
            (*gPartfxInterface)
                ->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_DUST_CLOUD, &gMmpAsteroidDustSpawnParams, 0x200001, -1,
                              &gMmpAsteroidDustHeightParam);
            (*gPartfxInterface)
                ->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_DUST_CLOUD, &gMmpAsteroidDustSpawnParams, 0x200001, -1,
                              &gMmpAsteroidDustHeightParam);
        }
    }
    if (state->eventFlags != 0)
    {
        if ((state->eventFlags & ASTEROIDRE_FX_SMOKE) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_SMOKE, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_SMOKE, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_SMOKE, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & ASTEROIDRE_FX_DEBRIS) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_DEBRIS, NULL, 2, -1, NULL);
        }
        if ((state->eventFlags & ASTEROIDRE_FX_EXPLODE) != 0)
        {
            int count;
            (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_EXPLODE, NULL, 1, -1, NULL);
            count = 0x28;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_EXPLODE_DEBRIS, NULL, 1, -1, NULL);
                count--;
            } while (count != 0);
            spawnExplosionLegacy(obj, lbl_803E452C, 1, 1, 0, 1, 0, 1, 0);
            CameraShake_Start(lbl_803E4530, lbl_803E4534, lbl_803E4538);
            doRumble(lbl_803E453C);
            state->eventFlags &= ~ASTEROIDRE_FX_EXPLODE;
        }
        if ((state->eventFlags & ASTEROIDRE_FX_IMPACT) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_IMPACT, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_IMPACT, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & ASTEROIDRE_FX_PERIODIC) != 0)
        {
            state->periodicFxTimer -= timeDelta;
            if (state->periodicFxTimer < lbl_803E4518)
            {
                state->periodicFxTimer = (f32)(int)randomGetRange(10, 0x3C);
                (*gPartfxInterface)->spawnObject((void*)obj, MMPASTEROIDRE_PARTFX_PERIODIC, NULL, 1, -1, NULL);
            }
        }
    }
    {
        f32 v = state->stateTimer;
        f32 k = lbl_803E4518;
        if (v > k)
        {
            state->stateTimer = v - timeDelta;
            if (state->stateTimer <= k)
            {
                mainSetBits(0x88B, 0);
            }
        }
    }
    state->eventFlags &= ~ASTEROIDRE_SEQ_TICK;
}

ObjectDescriptor gMMP_asteroid_reObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmp_asteroid_re_initialise,
    (ObjectDescriptorCallback)mmp_asteroid_re_release,
    0,
    (ObjectDescriptorCallback)mmp_asteroid_re_init,
    (ObjectDescriptorCallback)mmp_asteroid_re_update,
    (ObjectDescriptorCallback)mmp_asteroid_re_hitDetect,
    (ObjectDescriptorCallback)mmp_asteroid_re_render,
    (ObjectDescriptorCallback)mmp_asteroid_re_free,
    (ObjectDescriptorCallback)mmp_asteroid_re_getObjectTypeId,
    mmp_asteroid_re_getExtraSize,
};
