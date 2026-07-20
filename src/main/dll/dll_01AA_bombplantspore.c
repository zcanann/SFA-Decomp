/* DLL 0x01AA (bombplantspore) - Bomb plant spore projectile [0x801D3378-0x801D3FF4). */
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/obj_message.h"
#include "main/model_light.h"
#include "main/object.h"
#include "main/audio/sfx.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/dll_01AA_bombplantspore.h"
#include "main/gameloop_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

u8 lbl_803DBFC0[8] = {0x40, 0xA0, 0, 0, 0, 0, 0, 0};

typedef struct BombplantsporePlacement
{
    u8 pad0[0x1A - 0x0];
    s16 angleSpread;
    s16 baseAngle;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporePlacement;

typedef struct BombPlantSporeStateFlags
{
    u8 hitSurface : 1;
    u8 waitingForDetonateAck : 1;
    u8 unused : 6;
} BombPlantSporeStateFlags;

#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES     0x66c
#define BOMBPLANTSPORE_MSG_DETONATE             0x7000b
#define BOMBPLANTSPORE_MSG_HIT_PLAYER           0x7000a
#define BOMBPLANTSPORE_PLAYER_DAMAGE_TYPE       0x18e
#define BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT 10

/* burst spawned per particle on detonation (MSG_DETONATE / fuse timeout) */
#define BOMBPLANTSPORE_PARTFX_EXPLOSION 0x3f3
/* effect spawned once when the spore is created in BombPlantSpore_init */
#define BOMBPLANTSPORE_PARTFX_SPAWN 0x3f1

#define BOMBPLANTSPORE_OBJFLAG_HIDDEN             0x4000
#define BOMBPLANTSPORE_OBJFLAG_HITDETECT_DISABLED 0x2000

#define BOMBPLANTSPORE_FLAGS(state) ((BombPlantSporeStateFlags*)&(state)->stateFlags)

extern const f32 lbl_803E5390;
extern const f32 lbl_803E5394;
extern const f32 gBombPlantSporePi;
extern const f32 gBombPlantSporeAngleHalfPeriod;
extern const f32 lbl_803E53A8;
extern const f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern const f32 lbl_803E53B4;
extern u8 lbl_80326D98[];
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

int BombPlantSpore_getExtraSize(void)
{
    return 0x2b4;
}

void BombPlantSpore_free(GameObject* obj)
{
    BombPlantSporeState* state;
    ModelLightStruct* light;

    state = obj->extra;
    (*gExpgfxInterface)->freeSource((u32)obj);
    light = state->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
        state->light = NULL;
    }
}

void bombplantspore_startDriftBurst(GameObject* obj, BombPlantSporeState* state);
void bombplantspore_updateDrift(GameObject* obj, BombPlantSporeState* state);

void bombplantspore_startDriftBurst(GameObject* obj, BombPlantSporeState* state)
{
    s16 baseAngle;
    BombplantsporePlacement* params;
    s32 angleDelta;

    params = (BombplantsporePlacement*)obj->anim.placementData;
    baseAngle = params->baseAngle;

    state->spinTimer = (f32)(int)randomGetRange(0x1e, 0x2d);

    state->driftTimer = state->spinTimer + (f32)(int)randomGetRange(0x78, 0xb4);

    state->burstDriftAngle = (s16)(state->currentSpinAngle + randomGetRange(-2000, 2000));
    angleDelta = (s32)state->burstDriftAngle - (u16)baseAngle;
    if (0x8000 < angleDelta)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }
    if (angleDelta > params->angleSpread)
    {
        state->burstDriftAngle = (s16)(baseAngle + params->angleSpread);
    }
    if (angleDelta < -(s32)params->angleSpread)
    {
        state->burstDriftAngle = (s16)(baseAngle - params->angleSpread);
    }

    state->driftSpeedTarget = (f32)(int)randomGetRange(900, 0x514) / lbl_803E5390;
    state->driftSpeed = lbl_803E5394;

    state->driftSin =
        mathSinf((gBombPlantSporePi * (f32)state->burstDriftAngle) / gBombPlantSporeAngleHalfPeriod);
    state->driftCos =
        mathCosf((gBombPlantSporePi * (f32)state->burstDriftAngle) / gBombPlantSporeAngleHalfPeriod);
}

void bombplantspore_updateDrift(GameObject* obj, BombPlantSporeState* state)
{
    s16 baseAngle;
    BombplantsporePlacement* params;
    s32 angleDelta;

    params = (BombplantsporePlacement*)obj->anim.placementData;
    baseAngle = params->baseAngle;

    if (randomGetRange(0, 100) < 10 && state->spinChangeTimer <= lbl_803E5394)
    {
        state->spinAngle = randomGetRange(2000, 4000);
        if (randomGetRange(0, 1) != 0)
        {
            state->spinAngle = -state->spinAngle;
        }
        state->spinAngle += state->currentSpinAngle;
        angleDelta = (s32)state->spinAngle - (u16)baseAngle;
        if (angleDelta > 0x8000)
        {
            angleDelta -= 0xffff;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta += 0xffff;
        }
        if (angleDelta > params->angleSpread)
        {
            state->spinAngle = (s16)(baseAngle + params->angleSpread);
        }
        if (angleDelta < -(s32)params->angleSpread)
        {
            state->spinAngle = (s16)(baseAngle - params->angleSpread);
        }
        state->spinChangeTimer = lbl_803E53A8;
    }

    if (randomGetRange(0, 100) < 10 && state->spinChangeTimer <= lbl_803E5394)
    {
        state->randomPhase =
            state->driftAmplitude + (f32)(int)randomGetRange(-200, 200) / lbl_803E5390;
        if (state->randomPhase < lbl_803E53AC)
        {
            state->randomPhase = lbl_803E53AC;
        }
        else if (state->randomPhase > lbl_803E53B0)
        {
            state->randomPhase = lbl_803E53B0;
        }
    }

    angleDelta = (s32)state->spinAngle - (u16)state->currentSpinAngle;
    if (angleDelta > 0x8000)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }
    state->currentSpinAngle += (angleDelta * framesThisStep) >> 4;
    {
        f32 amplitude;
        f32 amplitudeStep =
            (state->randomPhase - (amplitude = state->driftAmplitude)) * lbl_803E53B4;
        state->driftAmplitude = amplitudeStep * timeDelta + amplitude;
    }

    state->driftBaseX =
        state->driftAmplitude *
        mathSinf((gBombPlantSporePi * (f32)state->currentSpinAngle) / gBombPlantSporeAngleHalfPeriod);
    state->driftBaseZ =
        state->driftAmplitude *
        mathCosf((gBombPlantSporePi * (f32)state->currentSpinAngle) / gBombPlantSporeAngleHalfPeriod);
}

void BombPlantSpore_update(GameObject* obj)
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

    state = obj->extra;
    if ((state->stateFlags >> 6 & 1) != 0u)
    {
        while (ObjMsg_Pop(obj, (u32*)&poppedMessage, &poppedSender, NULL) != 0)
        {
            switch (poppedMessage)
            {
            case BOMBPLANTSPORE_MSG_DETONATE:
                gameBitIncrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
                Sfx_PlayFromObject((u32)obj, SFXTRIG_sc_gemrun0122);
                (*gExpgfxInterface)->freeSource((u32)obj);
                for (i = 0; i < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; i++)
                {
                    objfx_spawnDirectionalBurst(obj, 5, lbl_803E53B0, 7, 1, 0x3c, lbl_803E53B8, NULL, 0);
                    (*gPartfxInterface)->spawnObject(obj, BOMBPLANTSPORE_PARTFX_EXPLOSION, NULL, 4, -1, NULL);
                }
                modelLightStruct_setEnabled(state->light, 0, lbl_803E53AC);
                state->detonateTimer = lbl_803E53BC;
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
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
                                        (f32)(lbl_803E53D8 * (double)(fuseCap - fuse) + lbl_803E53D0), NULL, 0);
        }
    }
    ObjHits_GetPriorityHit(obj, &hitObject, 0, 0);
    hitObj = *(void**)obj->anim.hitReactState;
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
        obj->anim.velocityY = lbl_803E53E0 * timeDelta + obj->anim.velocityY;
        if (obj->anim.velocityY < *(f32*)&gBombPlantSporeMinVelocityY)
        {
            obj->anim.velocityY = gBombPlantSporeMinVelocityY;
        }
        if (obj->anim.velocityY > lbl_803E5394)
        {
            obj->anim.velocityY *= gBombPlantSporeVelocityDamping;
        }
        if (obj->anim.velocityY < lbl_803E5394)
        {
            ObjHits_EnableObject(obj);
        }
        bombplantspore_updateDrift(obj, state);
        if (randomGetRange(0, 100) < 5 && state->driftTimer <= lbl_803E5394)
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
                f32 driftSpeed;
                f32 driftStep = (state->driftSpeedTarget - (driftSpeed = state->driftSpeed)) * lbl_803E53EC;
                state->driftSpeed = driftStep * timeDelta + driftSpeed;
            }
        }
        obj->anim.velocityX = state->driftSin * state->driftSpeed + state->driftBaseX;
        obj->anim.velocityZ = state->driftCos * state->driftSpeed + state->driftBaseZ;
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                obj->anim.velocityZ * timeDelta);
        (*gPathControlInterface)->update(obj, state->pathState, timeDelta);
        (*gPathControlInterface)->apply(obj, state->pathState);
        (*gPathControlInterface)->advance(obj, state->pathState, timeDelta);
        if (hitObj != NULL && (hitId = ((GameObject*)hitObj)->anim.seqId, hitId != 0x36d) && hitId != 0x198 &&
            hitId != 0x63c)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_sc_eatthefood16);
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
        ObjMsg_SendToObject(hitObj, BOMBPLANTSPORE_MSG_HIT_PLAYER, obj, (u32)state);
        BOMBPLANTSPORE_FLAGS(state)->waitingForDetonateAck = 1;
    }
    else
    {
        f32 fuse = state->fuseTimer - timeDelta;
        state->fuseTimer = fuse;
        if (fuse <= lbl_803E5394)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_en_majring2);
            (*gExpgfxInterface)->freeSource((u32)obj);
            for (j = 0; j < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; j++)
            {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E53B0, 7, 1, 0x3c, lbl_803E53B8, NULL, 0);
                (*gPartfxInterface)->spawnObject(obj, BOMBPLANTSPORE_PARTFX_EXPLOSION, NULL, 4, -1, NULL);
            }
            modelLightStruct_setEnabled(state->light, 0, lbl_803E53AC);
            state->detonateTimer = lbl_803E53BC;
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
        }
    }
}


void BombPlantSpore_init(GameObject* obj, void* param2)
{
    BombPlantSporeState* state;
    ModelLightStruct* light;
    f32 randomPhase;
    u32 randAsDouble[2];
    u8 events[8];

    state = (obj)->extra;
    events[0] = 5;
    state->fuseTimer = lbl_803E53F0;
    (obj)->objectFlags |= (BOMBPLANTSPORE_OBJFLAG_HIDDEN | BOMBPLANTSPORE_OBJFLAG_HITDETECT_DISABLED);
    (obj)->anim.velocityY = lbl_803E53F4;
    ObjHits_DisableObject(obj);
    state->spinAngle = randomGetRange(0, 0xffff);

    state->randomPhase = (f32)(int)randomGetRange(0, 1000) / lbl_803E5390;

    (*gPathControlInterface)->init(state->pathState, 0, 0x40002, 1);
    (*gPathControlInterface)->setup(state->pathState, 1, lbl_80326D98, lbl_803DBFC0, events);
    (*gPathControlInterface)->attachObject(obj, state->pathState);
    (*gPartfxInterface)->spawnObject(obj, BOMBPLANTSPORE_PARTFX_SPAWN, NULL, 4, -1, NULL);

    light = objCreateLight(obj, 1);
    if (light != NULL)
    {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(light, 0xff, 0, 0xff, 0);
        lightSetFieldBC_8001db14(light, 1);
        modelLightStruct_setDistanceAttenuation(light, lbl_803E5388, lbl_803E538C);
    }
    state->light = light;
    ObjMsg_AllocQueue(obj, 2);
    state->yawStep = randomGetRange(-0x200, 0x200);
}
