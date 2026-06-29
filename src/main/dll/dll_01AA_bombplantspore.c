/* DLL 0x01AA (bombplantspore) - Bomb plant spore projectile [0x801D3378-0x801D3FF4). */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/SH/SHrocketmushroom.h"
#include "main/sfa_shared_decls.h"

typedef struct BombplantsporeStartDriftBurstPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 angleSpread;
    s16 baseAngle;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeStartDriftBurstPlacement;

typedef struct BombplantsporeUpdateDriftPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 angleSpread;
    s16 baseAngle;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeUpdateDriftPlacement;

extern void ModelLightStruct_free(void* light);
extern int randomGetRange(int lo, int hi);
extern void* Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(void* obj, int sndId);


extern u8 framesThisStep;
extern f32 timeDelta;
extern const f32 lbl_803E5390;
extern const f32 lbl_803E5394;
extern const f32 gBombPlantSporePi;
extern const f32 gBombPlantSporeAngleHalfPeriod;
extern const f32 lbl_803E53A8;
extern const f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern const f32 lbl_803E53B4;

extern void Sfx_PlayFromObject(void* obj, int id);
extern int ObjMsg_Pop(void* obj, u32* outMessage, u32* outSender, u32* outParam);
extern void Obj_FreeObject(u8* obj);
extern void objMove(void* obj, f32 x, f32 y, f32 z);
extern void* objCreateLight(void* obj, int arg);
extern void modelLightStruct_setEnabled(void* light, int enabled, f32 scale);
extern void modelLightStruct_setLightKind(void* light, int value);
extern void modelLightStruct_setDiffuseColor(void* light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(void* light, int value);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern void ObjMsg_SendToObject(void* dst, int msg, void* src, void* payload);
extern void objfx_spawnDirectionalBurst(void* obj, u8 idx, f32 f8val, u8 kind, u8 mode, u8 chance, f32 mult, void* origin, int flags);
extern u8 lbl_80326D98[];
extern u8 lbl_803DBFC0;
extern f32 lbl_803E5388;
extern const f32 lbl_803E538C;
extern const f32 lbl_803E53B8;
extern const f32 lbl_803E53BC;
extern f32 lbl_803E53C0;
extern const f32 lbl_803E53C4;
extern const f32 lbl_803E53C8;
extern f64 lbl_803E53D0;
extern f64 lbl_803E53D8;
extern f32 lbl_803E53E0;
extern f32 gBombPlantSporeMinVelocityY;
extern const f32 gBombPlantSporeVelocityDamping;
extern const f32 lbl_803E53EC;
extern f32 lbl_803E53F0;
extern const f32 lbl_803E53F4;

int bombplantspore_getExtraSize(void)
{
    return 0x2b4;
}

void bombplantspore_free(void* obj)
{
    void* state;
    void* light;

    state = ((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource((u32)obj);
    light = ((BombPlantSporeState*)state)->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
        ((BombPlantSporeState*)state)->light = NULL;
    }
}

/* These two drift helpers' only callers (bombplantspore_update/init) live
 * in the BombPlantSpore TU (SHrocketmushroom.c). */
#pragma dont_inline on
void bombplantspore_startDriftBurst(void* obj, void* state)
{
    s16 baseAngle;
    void* params;
    s32 angleDelta;

    params = ((GameObject*)obj)->anim.placementData;
    baseAngle = ((BombplantsporeStartDriftBurstPlacement*)params)->baseAngle;

    ((BombPlantSporeState*)state)->spinTimer = (f32)(int)
    randomGetRange(0x1e, 0x2d);

    ((BombPlantSporeState*)state)->driftTimer =
        ((BombPlantSporeState*)state)->spinTimer + (f32)(int)
    randomGetRange(0x78, 0xb4);

    ((BombPlantSporeState*)state)->burstDriftAngle =
        (s16)(((BombPlantSporeState*)state)->currentSpinAngle + randomGetRange(-2000, 2000));
    angleDelta = (s32)((BombPlantSporeState*)state)->burstDriftAngle - (u16)baseAngle;
    if (0x8000 < angleDelta)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }
    if (angleDelta > ((BombplantsporeStartDriftBurstPlacement*)params)->angleSpread)
    {
        ((BombPlantSporeState*)state)->burstDriftAngle = (s16)(
            baseAngle + ((BombplantsporeStartDriftBurstPlacement*)params)->angleSpread);
    }
    if (angleDelta < -(s32)((BombplantsporeStartDriftBurstPlacement*)params)->angleSpread)
    {
        ((BombPlantSporeState*)state)->burstDriftAngle = (s16)(
            baseAngle - ((BombplantsporeStartDriftBurstPlacement*)params)->angleSpread);
    }

    ((BombPlantSporeState*)state)->driftSpeedTarget = (f32)(int)
    randomGetRange(900, 0x514) / lbl_803E5390;
    ((BombPlantSporeState*)state)->driftSpeed = lbl_803E5394;

    ((BombPlantSporeState*)state)->driftSin =
        mathSinf((gBombPlantSporePi * (f32)((BombPlantSporeState*)state)->burstDriftAngle) / gBombPlantSporeAngleHalfPeriod);
    ((BombPlantSporeState*)state)->driftCos =
        mathCosf((gBombPlantSporePi * (f32)((BombPlantSporeState*)state)->burstDriftAngle) / gBombPlantSporeAngleHalfPeriod);
}

void bombplantspore_updateDrift(void* obj, void* state)
{
    s16 baseAngle;
    void* params;
    s32 angleDelta;

    params = ((GameObject*)obj)->anim.placementData;
    baseAngle = ((BombplantsporeUpdateDriftPlacement*)params)->baseAngle;

    if (randomGetRange(0, 100) < 10 && ((BombPlantSporeState*)state)->spinChangeTimer <= lbl_803E5394)
    {
        ((BombPlantSporeState*)state)->spinAngle = randomGetRange(2000, 4000);
        if (randomGetRange(0, 1) != 0)
        {
            ((BombPlantSporeState*)state)->spinAngle = -((BombPlantSporeState*)state)->spinAngle;
        }
        ((BombPlantSporeState*)state)->spinAngle += ((BombPlantSporeState*)state)->currentSpinAngle;
        angleDelta = (s32)((BombPlantSporeState*)state)->spinAngle - (u16)baseAngle;
        if (angleDelta > 0x8000)
        {
            angleDelta -= 0xffff;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta += 0xffff;
        }
        if (angleDelta > ((BombplantsporeUpdateDriftPlacement*)params)->angleSpread)
        {
            ((BombPlantSporeState*)state)->spinAngle = (s16)(
                baseAngle + ((BombplantsporeUpdateDriftPlacement*)params)->angleSpread);
        }
        if (angleDelta < -(s32)((BombplantsporeUpdateDriftPlacement*)params)->angleSpread)
        {
            ((BombPlantSporeState*)state)->spinAngle = (s16)(
                baseAngle - ((BombplantsporeUpdateDriftPlacement*)params)->angleSpread);
        }
        ((BombPlantSporeState*)state)->spinChangeTimer = lbl_803E53A8;
    }

    if (randomGetRange(0, 100) < 10 && ((BombPlantSporeState*)state)->spinChangeTimer <= lbl_803E5394)
    {
        ((BombPlantSporeState*)state)->randomPhase =
            ((BombPlantSporeState*)state)->driftAmplitude + (f32)(int)
        randomGetRange(-200, 200) / lbl_803E5390;
        if (((BombPlantSporeState*)state)->randomPhase < lbl_803E53AC)
        {
            ((BombPlantSporeState*)state)->randomPhase = lbl_803E53AC;
        }
        else if (((BombPlantSporeState*)state)->randomPhase > lbl_803E53B0)
        {
            ((BombPlantSporeState*)state)->randomPhase = lbl_803E53B0;
        }
    }

    angleDelta = (s32)((BombPlantSporeState*)state)->spinAngle - (u16)((BombPlantSporeState*)state)->currentSpinAngle;
    if (angleDelta > 0x8000)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }
    ((BombPlantSporeState*)state)->currentSpinAngle += (angleDelta * framesThisStep) >> 4;
    {
        f32 amplitude = ((BombPlantSporeState*)state)->driftAmplitude;
        f32 amplitudeStep = lbl_803E53B4 * (((BombPlantSporeState*)state)->randomPhase - amplitude);
        ((BombPlantSporeState*)state)->driftAmplitude = amplitudeStep * timeDelta + amplitude;
    }

    ((BombPlantSporeState*)state)->driftBaseX =
        ((BombPlantSporeState*)state)->driftAmplitude *
        mathSinf((gBombPlantSporePi * (f32)((BombPlantSporeState*)state)->currentSpinAngle) / gBombPlantSporeAngleHalfPeriod);
    ((BombPlantSporeState*)state)->driftBaseZ =
        ((BombPlantSporeState*)state)->driftAmplitude *
        mathCosf((gBombPlantSporePi * (f32)((BombPlantSporeState*)state)->currentSpinAngle) / gBombPlantSporeAngleHalfPeriod);
}
#pragma dont_inline reset

void bombplant_init(void* obj, void* param, int flag);

#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES 0x66c
#define BOMBPLANTSPORE_MSG_DETONATE 0x7000b
#define BOMBPLANTSPORE_MSG_HIT_PLAYER 0x7000a
#define BOMBPLANTSPORE_PLAYER_DAMAGE_TYPE 0x18e
#define BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT 10

typedef struct BombPlantSporeStateFlags {
    u8 hitSurface : 1;
    u8 waitingForDetonateAck : 1;
    u8 unused : 6;
} BombPlantSporeStateFlags;

#define BOMBPLANTSPORE_FLAGS(state) ((BombPlantSporeStateFlags*)&(state)->stateFlags)

void bombplantspore_update(void* obj)
{
    BombPlantSporeState* state;
    s32 particleAlpha;
    s16 hitId;
    void* hitObj;
    int poppedMessage;
    u32 poppedSender;
    int hitObject;
    void* playerObj;
    int detonateMessage;
    int i;
    int j;

    state = ((GameObject*)obj)->extra;
    if ((state->stateFlags >> 6 & 1) != 0u)
    {
        while (ObjMsg_Pop(obj, (u32*)&poppedMessage, &poppedSender, NULL) != 0)
        {
            switch (poppedMessage)
            {
            case BOMBPLANTSPORE_MSG_DETONATE:
                gameBitIncrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
                Sfx_PlayFromObject(obj, SFXmv_totem_slide);
                (*gExpgfxInterface)->freeSource((u32)obj);
                for (i = 0; i < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; i++)
                {
                    objfx_spawnDirectionalBurst(obj, 5, lbl_803E53B0, 7, 1, 0x3c, lbl_803E53B8, NULL, 0);
                    (*gPartfxInterface)->spawnObject(obj, 0x3f3, NULL, 4, -1, NULL);
                }
                modelLightStruct_setEnabled(state->light, 0, lbl_803E53AC);
                state->detonateTimer = lbl_803E53BC;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject((u32)obj);
                BOMBPLANTSPORE_FLAGS(state)->waitingForDetonateAck = 0;
                break;
            }
        }
        if ((state->stateFlags >> 6 & 1) != 0u)
        {
            return;
        }
    }

    if (state->detonateTimer != lbl_803E5394)
    {
        *(s16*)obj += framesThisStep * 0x40;
        state->detonateTimer -= timeDelta;
        if (state->detonateTimer <= lbl_803E5394)
        {
            Obj_FreeObject(obj);
        }
        return;
    }

    {
        f32 fuse = state->fuseTimer;
        f32 fuseCap = lbl_803E53C0;
        if (fuse < fuseCap)
        {
            particleAlpha = (s32) - (lbl_803E53C8 * fuse - lbl_803E53C4);
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E53B0, 7, 1, particleAlpha & 0xff,
                                        (f32)(lbl_803E53D8 *
                                            (double)(fuseCap - fuse) +
                                            lbl_803E53D0),
                                        NULL, 0);
        }
    }
    ObjHits_GetPriorityHit((int)obj, &hitObject, 0, 0);
    hitObj = *(void**)((GameObject*)obj)->anim.hitReactState;
    if (BOMBPLANTSPORE_FLAGS(state)->hitSurface == 0)
    {
        state->driftTimer -= timeDelta;
        if (state->driftTimer < *(f32*)&lbl_803E5394)
        {
            state->driftTimer = lbl_803E5394;
        }
        state->spinChangeTimer -= timeDelta;
        if (state->spinChangeTimer < *(f32*)&lbl_803E5394)
        {
            state->spinChangeTimer = lbl_803E5394;
        }
        *(s16*)obj += state->yawStep;
        ((GameObject*)obj)->anim.velocityY = lbl_803E53E0 * timeDelta + ((GameObject*)obj)->anim.velocityY;
        if (((GameObject*)obj)->anim.velocityY < *(f32*)&gBombPlantSporeMinVelocityY)
        {
            ((GameObject*)obj)->anim.velocityY = gBombPlantSporeMinVelocityY;
        }
        if (((GameObject*)obj)->anim.velocityY > lbl_803E5394)
        {
            ((GameObject*)obj)->anim.velocityY *= gBombPlantSporeVelocityDamping;
        }
        if (((GameObject*)obj)->anim.velocityY < lbl_803E5394)
        {
            ObjHits_EnableObject((u32)obj);
        }
        bombplantspore_updateDrift(obj, state);
        if (randomGetRange(0, 100) < 5 &&
            state->driftTimer <= lbl_803E5394)
        {
            bombplantspore_startDriftBurst(obj, state);
        }
        {
            f32 st = state->spinTimer - timeDelta;
            state->spinTimer = st;
            if (st <= lbl_803E5394)
            {
                state->driftSin *= gBombPlantSporeVelocityDamping;
                state->driftCos *= gBombPlantSporeVelocityDamping;
                state->spinTimer = lbl_803E5394;
            }
            else
            {
                f32 driftSpeed = state->driftSpeed;
                f32 driftStep = lbl_803E53EC * (state->driftSpeedTarget - driftSpeed);
                state->driftSpeed = driftStep * timeDelta + driftSpeed;
            }
        }
        ((GameObject*)obj)->anim.velocityX =
            state->driftSin * state->driftSpeed +
            state->driftBaseX;
        ((GameObject*)obj)->anim.velocityZ =
            state->driftCos * state->driftSpeed +
            state->driftBaseZ;
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        (*gPathControlInterface)->update(obj, state->pathState, timeDelta);
        (*gPathControlInterface)->apply(obj, state->pathState);
        (*gPathControlInterface)->advance(obj, state->pathState, timeDelta);
        if (hitObj != NULL &&
            (hitId = *(s16*)((u8*)hitObj + 0x46), hitId != 0x36d) &&
            hitId != 0x198 && hitId != 0x63c)
        {
            Sfx_PlayFromObject(obj, SFXen_tiles_lightup);
            BOMBPLANTSPORE_FLAGS(state)->hitSurface = 1;
            if (state->fuseTimer > *(f32*)&lbl_803E53C0)
            {
                state->fuseTimer = lbl_803E53C0;
            }
        }
        if ((*(s8*)((u8*)state + 0x268) & 0x11) != 0)
        {
            BOMBPLANTSPORE_FLAGS(state)->hitSurface = 1;
            if (state->fuseTimer > *(f32*)&lbl_803E53C0)
            {
                state->fuseTimer = lbl_803E53C0;
            }
        }
    }
    playerObj = Obj_GetPlayerObject();
    if (hitObj == playerObj)
    {
        state->damageType = BOMBPLANTSPORE_PLAYER_DAMAGE_TYPE;
        ObjMsg_SendToObject(hitObj, BOMBPLANTSPORE_MSG_HIT_PLAYER, obj, state);
        BOMBPLANTSPORE_FLAGS(state)->waitingForDetonateAck = 1;
    }
    else
    {
        f32 fuse = state->fuseTimer - timeDelta;
        state->fuseTimer = fuse;
        if (fuse <= lbl_803E5394)
        {
            Sfx_PlayFromObject(obj, SFXmv_torclp_6);
            (*gExpgfxInterface)->freeSource((u32)obj);
            for (j = 0; j < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; j++)
            {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E53B0, 7, 1, 0x3c, lbl_803E53B8, NULL, 0);
                (*gPartfxInterface)->spawnObject(obj, 0x3f3, NULL, 4, -1, NULL);
            }
            modelLightStruct_setEnabled(state->light, 0, lbl_803E53AC);
            state->detonateTimer = lbl_803E53BC;
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject((u32)obj);
        }
    }
}

void bombplantspore_init(void* obj, void* param2)
{
    BombPlantSporeState* state;
    void* light;
    f32 randomPhase;
    u32 randAsDouble[2];
    u8 events[8];

    state = ((GameObject*)obj)->extra;
    events[0] = 5;
    state->fuseTimer = lbl_803E53F0;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    ((GameObject*)obj)->anim.velocityY = lbl_803E53F4;
    ObjHits_DisableObject((u32)obj);
    state->spinAngle = randomGetRange(0, 0xffff);

    state->randomPhase = (f32)(int)
    randomGetRange(0, 1000) / lbl_803E5390;

    (*gPathControlInterface)->init(state->pathState, 0, 0x40002, 1);
    (*gPathControlInterface)->setup(state->pathState, 1, lbl_80326D98, &lbl_803DBFC0, events);
    (*gPathControlInterface)->attachObject(obj, state->pathState);
    (*gPartfxInterface)->spawnObject(obj, 0x3f1, NULL, 4, -1, NULL);

    light = objCreateLight(obj, 1);
    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, 2);
        modelLightStruct_setDiffuseColor(light, 0xff, 0, 0xff, 0);
        lightSetFieldBC_8001db14(light, 1);
        modelLightStruct_setDistanceAttenuation(light, lbl_803E5388, lbl_803E538C);
    }
    state->light = light;
    ObjMsg_AllocQueue(obj, 2);
    state->yawStep = randomGetRange(-0x200, 0x200);
}
