/*
 * mmpasteroidre (DLL 0x180) - Moon Mountain Pass asteroid re-entry object.
 *
 * A scripted falling asteroid. The sequence callback (fn_801A6F4C)
 * consumes anim events to toggle lighting and drive phase transitions
 * (eventFlags / gamebit 0x87B). init seeds intensity (gamebit 0x88C) and
 * phase, restoring the right visual state on load. update integrates the
 * descent - gravity-like vertical motion toward a target height with a
 * sine wobble on position and rotation, looped re-entry sfx scaled by
 * intensity, and per-flag particle bursts (trails, sparks, the impact
 * explosion with camera shake + rumble). The state timer clears gamebit
 * 0x88B when it expires.
 */

#include "main/dll/MMP/mmp_asteroid_re_state.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"

#define MMPASTEROIDRE_OBJFLAG_HIDDEN 0x4000
#define MMPASTEROIDRE_OBJFLAG_HITDETECT_DISABLED 0x2000

STATIC_ASSERT(sizeof(MmpAsteroidReState) == 0x1C);


extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 volume, f32 scale);
extern void setDrawLights(int v);
extern int objMove(u8* obj, f32 dx, f32 dy, f32 dz);
extern void objRenderFn_8003b8f4(f32 v);


extern f32 gMmpAsteroidIntensityHeightTable[];
extern PartFxSpawnParams gMmpAsteroidDustSpawnParams;
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

void mmp_asteroid_re_update(int obj);

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

int mmp_asteroid_re_getExtraSize(void) { return 0x1c; }
int mmp_asteroid_re_getObjectTypeId(void) { return 0x0; }

#pragma peephole off
void mmp_asteroid_re_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E44F8);
}

#pragma scheduling off
int fn_801A6F4C(int obj, int unused, ObjAnimUpdateState* animUpdate)
{

    MmpAsteroidReState * state = ((GameObject*)obj)->extra;
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
            state->phase = 1;
            GameBit_Set(0x87b, state->phase);
            ((GameObject*)obj)->anim.alpha = 0xff;
            break;
        case 2:
            state->eventFlags = state->eventFlags & ~9;
            state->eventFlags = state->eventFlags | 0x30;
            ((ObjAnimComponent*)obj)->bankIndex = 1;
            break;
        case 3:
            {
                int r;
                state->eventFlags = state->eventFlags & ~0x20;
                state->eventFlags = state->eventFlags | 0x50;
                r = randomGetRange(10, 60);
                state->periodicFxTimer = r;
                state->phase = 1;
                GameBit_Set(0x87b, state->phase);
                break;
            }
        case 4:
            state->stateTimer = lbl_803E44E8;
            setDrawLights(1);
            break;
        }
    }
    state->eventFlags |= 0x80;
    mmp_asteroid_re_update(obj);
    return 0;
}

void mmp_asteroid_re_init(int obj)
{
    MmpAsteroidReState * state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags |= (MMPASTEROIDRE_OBJFLAG_HIDDEN | MMPASTEROIDRE_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->animEventCallback = fn_801A6F4C;
    state->eventFlags = 0;
    state->intensity = GameBit_Get(0x88C);
    state->phase = GameBit_Get(0x87B);
    switch ((s32)state->phase)
    {
    case 0:
        ((GameObject*)obj)->anim.alpha = 0;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 0;
        break;
    case 1:
        ((GameObject*)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 1;
        state->eventFlags |= 0x40;
        break;
    case 2:
        ((GameObject*)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 1;
        break;
    case 3:
        ((GameObject*)obj)->anim.alpha = 0xFF;
        state->eventFlags = 4;
        *(u8*)&((GameObject*)obj)->anim.bankIndex = 1;
        break;
    }
    {
        f32 v = ((GameObject*)obj)->anim.localPosY;
        state->baseY = v;
        state->baseY2 = v;
    }
}

void mmp_asteroid_re_update(int obj)
{

    extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);

    MmpAsteroidReState * state = ((GameObject*)obj)->extra;
    if ((state->eventFlags & 0x80) == 0)
    {
        if (GameBit_Get(0xD52) != 0)
        {
            state->intensity = 1;
        }
        else
        {
            state->intensity = GameBit_Get(0x88C);
        }
        state->phase = 2;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_lwfl1_c);
        {
            int vol = state->intensity * 0x20 + 0x20;
            if (vol > 0x7F)
            {
                vol = 0x7F;
            }
            Sfx_SetObjectChannelVolume(obj, 0x40, vol, lbl_803E44FC);
        }
        if (state->intensity != 0)
        {
            f32 speed = ((GameObject*)obj)->anim.velocityY;
            if (speed < lbl_803E4500 * ((state->baseY + gMmpAsteroidIntensityHeightTable[state->intensity]) - ((GameObject*)
                obj)->anim.localPosY))
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
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + mathSinf(
                (gMmpAsteroidPi * state->bobPhase) / lbl_803E4520);
            if (((GameObject*)obj)->anim.localPosY < state->baseY)
            {
                ((GameObject*)obj)->anim.localPosY = state->baseY;
            }
            ((GameObject*)obj)->anim.rotZ = (s16)(
                ((GameObject*)obj)->anim.rotZ + (int)(lbl_803E4524 * mathSinf(
                    (gMmpAsteroidPi * state->rollPhase) / lbl_803E4520)));
            ((GameObject*)obj)->anim.rotY = (s16)(
                ((GameObject*)obj)->anim.rotY + (int)(lbl_803E4524 * mathSinf(
                    (gMmpAsteroidPi * state->pitchPhase) / lbl_803E4520)));
            gMmpAsteroidDustSpawnParams.scale = lbl_803E44F8;
            gMmpAsteroidDustSpawnParams.posX = ((GameObject*)obj)->anim.localPosX;
            gMmpAsteroidDustSpawnParams.posY = state->baseY - lbl_803E4528;
            gMmpAsteroidDustSpawnParams.posZ = ((GameObject*)obj)->anim.localPosZ;
            gMmpAsteroidDustHeightParam = (int)(((GameObject*)obj)->anim.localPosY - state->baseY);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x722, NULL, 2, -1, &gMmpAsteroidDustHeightParam);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x723, &gMmpAsteroidDustSpawnParams, 0x200001, -1,
                                             &gMmpAsteroidDustHeightParam);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x723, &gMmpAsteroidDustSpawnParams, 0x200001, -1,
                                             &gMmpAsteroidDustHeightParam);
        }
    }
    if (state->eventFlags != 0)
    {
        if ((state->eventFlags & 1) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x716, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x716, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x716, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & 8) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71A, NULL, 2, -1, NULL);
        }
        if ((state->eventFlags & 0x10) != 0)
        {
            int n;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71B, NULL, 1, -1, NULL);
            n = 0x28;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x71C, NULL, 1, -1, NULL);
                n--;
            }
            while (n != 0);
            spawnExplosion(obj, lbl_803E452C, 1, 1, 0, 1, 0, 1, 0);
            CameraShake_Start(lbl_803E4530, lbl_803E4534, lbl_803E4538);
            doRumble(lbl_803E453C);
            state->eventFlags &= ~0x10;
        }
        if ((state->eventFlags & 0x20) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71D, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x71D, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & 0x40) != 0)
        {
            state->periodicFxTimer -= timeDelta;
            if (state->periodicFxTimer < lbl_803E4518)
            {
                state->periodicFxTimer = (f32)(int)
                randomGetRange(10, 0x3C);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x71E, NULL, 1, -1, NULL);
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
                GameBit_Set(0x88B, 0);
            }
        }
    }
    state->eventFlags &= ~0x80;
}
