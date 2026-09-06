/*
 * DrakorEnerg (DLL 0x241) - the floating Krazoa-energy orb spawned during
 * the Drakor boss fight. Its extra block (DrakorEnergyState, 0xC bytes) runs
 * a small mode machine: it idles until its placement game bit is set, falls
 * and bounces to a resting height, bobs on a sine wave while drifting, then
 * homes on the player and, on contact, restores health and is collected.
 *
 * mode: 0 idle (wait for game bit) -> 2 bobbing; 1 falling/bounce;
 *       2 bobbing+seek player; 3 chasing/intercept; 4 collected; 5 reset.
 *
 * The standard object hooks (init/update/render/getExtraSize/...) are wired
 * through the DLL's ObjectDescriptor elsewhere; rendering uses a shared glow
 * draw helper (objRenderModelAndHitVolumes) and particle bursts come from
 * gPartfxInterface / objfx_spawnFlaggedTrailBurst.
 */
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/objfx.h"
#include "main/dll/partfx_interface.h"
#include "dolphin/mtx/vec.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/player_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/object_render.h"
#include "main/gamebits.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0241_drakorenergy.h"

f32 gDrakorEnergyBobAmplitude = 3.0f;
f32 gDrakorEnergySeekRange = 900.0f;
f32 gDrakorEnergyCollectRadius = 20.0f;
f32 gDrakorEnergyChaseSpeed = 7.0f;
int gDrakorEnergyHealAmount = 1;
f32 gDrakorEnergyTrailScale = 0.4f;
s16 gDrakorEnergySpinStep = 0x200;

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

/* DrakorEnergyState.mode values (see file header comment) */
#define DRAKORENERGY_PARTFX         0x357
#define DRAKORENERGY_MODE_IDLE      0 /* wait for the placement game bit */
#define DRAKORENERGY_MODE_FALLING   1 /* fall + bounce to a resting height */
#define DRAKORENERGY_MODE_BOBBING   2 /* sine bob + seek the player */
#define DRAKORENERGY_MODE_CHASING   3 /* intercept/chase, heal on contact */
#define DRAKORENERGY_MODE_COLLECTED 4 /* collected (hidden, no update) */
#define DRAKORENERGY_MODE_RESET     5 /* one-frame reset back to IDLE */
void DrakorEnergy_func0B_nop(void)
{
}

int drakorenergy_isIdle(GameObject* obj)
{
    return ((DrakorEnergyState*)obj->extra)->mode == DRAKORENERGY_MODE_IDLE;
}

int drakorenergy_getExtraSize(void)
{
    return sizeof(DrakorEnergyState);
}
int drakorenergy_getObjectTypeId(void)
{
    return 0x0;
}

void drakorenergy_free(void)
{
}

void drakorenergy_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    DrakorEnergyState* state = obj->extra;
    u32 mode = state->mode;
    if (mode != DRAKORENERGY_MODE_IDLE && mode != DRAKORENERGY_MODE_COLLECTED)
    {
        objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
    }
}

void drakorenergy_hitDetect(void)
{
}

void drakorenergy_update(GameObject* o)
{
    DrakorEnergyState* state = (DrakorEnergyState*)o->extra;
    DrakorenergyPlacement* placement;
    GameObject* player;
    f32 zeroF;
    f32 dist;
    f32 spd;
    Vec interceptPt;
    Vec seekDir;
    PartFxSpawnParams colorRGB;
    DrakorEnergyState* s = state;

    player = Obj_GetPlayerObject();
    placement = (DrakorenergyPlacement*)o->anim.placementData;
    switch (s->mode)
    {
    case DRAKORENERGY_MODE_IDLE:
        if (mainGetBit(placement->gameBitId) == 1)
        {
            s->mode = DRAKORENERGY_MODE_BOBBING;
        }
        break;
    case DRAKORENERGY_MODE_FALLING:
        if (s->startY - o->anim.localPosY > (zeroF = 0.0f))
        {
            o->anim.velocityY = 0.7f * -o->anim.velocityY;
            dist = (o->anim.velocityY >= zeroF) ? o->anim.velocityY
                                                                 : -o->anim.velocityY;
            if (dist < 0.1f)
            {
                s->mode = DRAKORENERGY_MODE_BOBBING;
                zeroF = 0.0f;
                o->anim.velocityX = zeroF;
                o->anim.velocityZ = zeroF;
                break;
            }
        }
        o->anim.velocityY += -0.4f;
        objMove(o, o->anim.velocityX, o->anim.velocityY,
                o->anim.velocityZ);
        colorRGB.arg2 = 0xff;
        colorRGB.arg1 = 0xff - s->phase % 0x500;
        colorRGB.arg0 = 0xff;
        (*gPartfxInterface)->spawnObject((void*)o, DRAKORENERGY_PARTFX, &colorRGB, 0, -1, NULL);
        break;
    case DRAKORENERGY_MODE_BOBBING:
        o->anim.velocityY =
            gDrakorEnergyBobAmplitude *
            mathSinf(3.14159274f * (f32)s->phase / 32768.0f);
        objMove(o, o->anim.velocityX, o->anim.velocityY,
                o->anim.velocityZ);
        if (Vec_distance(&o->anim.worldPosX, &player->anim.worldPosX) <
            gDrakorEnergySeekRange)
        {
            s->mode = DRAKORENERGY_MODE_CHASING;
        }
        objfx_spawnFlaggedTrailBurst((void*)o, gDrakorEnergyTrailScale, 1, 0xc22, 0x14, (void*)&o->anim.velocity);
        break;
    case DRAKORENERGY_MODE_CHASING:
        dist = Vec_xzDistance(&o->anim.worldPosX, &player->anim.worldPosX);
        if (dist < gDrakorEnergyCollectRadius)
        {
            playerAddHealth(player, gDrakorEnergyHealAmount);
            Sfx_PlayFromObject(o, SFXTRIG_lockoff22);
            s->mode = DRAKORENERGY_MODE_COLLECTED;
        }
        else
        {
            spd = gDrakorEnergyChaseSpeed;
            Obj_PredictInterceptPoint(player, spd / 1.2f,
                                      &o->anim.localPos, &interceptPt);
            PSVECSubtract(&interceptPt, &o->anim.localPos, &seekDir);
            PSVECNormalize(&seekDir, &seekDir);
            if (dist < spd)
            {
                spd = dist;
            }
            PSVECScale(&seekDir, &o->anim.velocity, spd);
            objMove(o, o->anim.velocityX * timeDelta, o->anim.velocityY * timeDelta,
                    o->anim.velocityZ * timeDelta);
            colorRGB.arg2 = 0xff;
            colorRGB.arg1 = 0;
            colorRGB.arg0 = 0xff;
            objfx_spawnFlaggedTrailBurst((void*)o, gDrakorEnergyTrailScale, 1, 0xc22, 0x14, (void*)&o->anim.velocity);
        }
        break;
    case DRAKORENERGY_MODE_RESET:
        s->mode = DRAKORENERGY_MODE_IDLE;
        break;
    }
    *(s16*)o += gDrakorEnergySpinStep;
    s->phase += framesThisStep * 0x500;
}

void drakorenergy_init(GameObject* obj, DrakorenergyPlacement* placement)
{
    DrakorEnergyState* state;
    f32 fz;
    state = obj->extra;
    state->mode = DRAKORENERGY_MODE_RESET;
    obj->anim.localPosX = placement->base.posX;
    obj->anim.localPosY = placement->base.posY;
    obj->anim.localPosZ = placement->base.posZ;
    fz = 0.0f;
    obj->anim.velocityZ = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = -4.0f;
    state->phase = randomGetRange(0, 0xffff);
    if (mainGetBit(placement->gameBitId) != 0)
    {
        state->mode = DRAKORENERGY_MODE_COLLECTED;
    }
}

void drakorenergy_release(void)
{
}

void drakorenergy_initialise(void)
{
}

ObjectDescriptor12 gDrakorEnergyObjDescriptor = {
    0,
    0,
    0,
    0xB0000,
    (ObjectDescriptorCallback)drakorenergy_initialise,
    (ObjectDescriptorCallback)drakorenergy_release,
    0,
    (ObjectDescriptorCallback)drakorenergy_init,
    (ObjectDescriptorCallback)drakorenergy_update,
    (ObjectDescriptorCallback)drakorenergy_hitDetect,
    (ObjectDescriptorCallback)drakorenergy_render,
    (ObjectDescriptorCallback)drakorenergy_free,
    (ObjectDescriptorCallback)drakorenergy_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)drakorenergy_getExtraSize,
    (ObjectDescriptorCallback)drakorenergy_isIdle,
    (ObjectDescriptorCallback)DrakorEnergy_func0B_nop,
};
