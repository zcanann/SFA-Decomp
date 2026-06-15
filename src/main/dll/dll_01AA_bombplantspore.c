/* DLL 0x01AA (bombplantspore) — Bomb plant spore projectile [0x801D3378-0x801D3FF4). */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/SH/SHrocketmushroom.h"

typedef struct BombplantsporeStartDriftBurstPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeStartDriftBurstPlacement;

typedef struct BombplantsporeUpdateDriftPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeUpdateDriftPlacement;

extern void ModelLightStruct_free(void* light);
extern int randomGetRange(int min, int max);
extern void* Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(void* obj, int sndId);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);


extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5390;
extern f32 lbl_803E5394;
extern f32 lbl_803E5398;
extern f32 lbl_803E539C;
extern f32 lbl_803E53A8;
extern f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern f32 lbl_803E53B4;

extern int gameBitIncrement(int bit);
extern void Sfx_PlayFromObject(void* obj, int id);
extern int ObjMsg_Pop(void* obj, u32* outMessage, u32* outSender, u32* outParam);
extern void Obj_FreeObject(void* obj);
extern void objMove(f32 x, f32 y, f32 z, void* obj);
extern void* objCreateLight(void* obj, int arg);
extern void modelLightStruct_setEnabled(void* light, int enabled, f32 scale);
extern void modelLightStruct_setLightKind(void* light, int value);
extern void modelLightStruct_setDiffuseColor(void* light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(void* light, int value);
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 min, f32 max);
extern void ObjMsg_AllocQueue(void* obj, int count);
extern void ObjMsg_SendToObject(void* dst, int msg, void* src, void* payload);
extern void objfx_spawnDirectionalBurst(void* obj, u8 idx, u8 kind, u8 mode, u8 chance, void* origin,
                                        int flags, f32 f8val, f32 mult);
extern u8 lbl_80326D98[];
extern u8 lbl_803DBFC0;
extern f32 lbl_803E5388;
extern f32 lbl_803E538C;
extern f32 lbl_803E53B8;
extern f32 lbl_803E53BC;
extern f32 lbl_803E53C0;
extern f32 lbl_803E53C4;
extern f32 lbl_803E53C8;
extern f64 lbl_803E53D0;
extern f64 lbl_803E53D8;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53E4;
extern f32 lbl_803E53E8;
extern f32 lbl_803E53EC;
extern f32 lbl_803E53F0;
extern f32 lbl_803E53F4;

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

/* Keep the cross-TU bl: these two drift helpers' only callers
 * (bombplantspore_update/init) live in the BombPlantSpore TU
 * (SHrocketmushroom.c). Once they land there, dont_inline stops MWCC
 * auto-inlining them into bombplantspore_update. */
#pragma dont_inline on
void bombplantspore_startDriftBurst(void* obj, void* state)
{
    s16 baseAngle;
    void* params;
    s32 angleDelta;

    params = ((GameObject*)obj)->anim.placementData;
    baseAngle = ((BombplantsporeStartDriftBurstPlacement*)params)->unk1C;

    ((BombPlantSporeState*)state)->spinTimer = (f32)(int)
    randomGetRange(0x1e, 0x2d);

    ((BombPlantSporeState*)state)->driftTimer =
        ((BombPlantSporeState*)state)->spinTimer + (f32)(int)
    randomGetRange(0x78, 0xb4);

    ((BombPlantSporeState*)state)->unk2aa =
        (s16)(((BombPlantSporeState*)state)->unk2a8 + randomGetRange(-2000, 2000));
    angleDelta = (s32)((BombPlantSporeState*)state)->unk2aa - (u16)baseAngle;
    if (0x8000 < angleDelta)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }
    if (angleDelta > ((BombplantsporeStartDriftBurstPlacement*)params)->unk1A)
    {
        ((BombPlantSporeState*)state)->unk2aa = (s16)(
            baseAngle + ((BombplantsporeStartDriftBurstPlacement*)params)->unk1A);
    }
    if (angleDelta < -(s32)((BombplantsporeStartDriftBurstPlacement*)params)->unk1A)
    {
        ((BombPlantSporeState*)state)->unk2aa = (s16)(
            baseAngle - ((BombplantsporeStartDriftBurstPlacement*)params)->unk1A);
    }

    ((BombPlantSporeState*)state)->driftSpeedTarget = (f32)(int)
    randomGetRange(900, 0x514) / lbl_803E5390;
    ((BombPlantSporeState*)state)->driftSpeed = lbl_803E5394;

    ((BombPlantSporeState*)state)->driftSin =
        mathSinf((lbl_803E5398 * (f32)((BombPlantSporeState*)state)->unk2aa) / lbl_803E539C);
    ((BombPlantSporeState*)state)->driftCos =
        mathCosf((lbl_803E5398 * (f32)((BombPlantSporeState*)state)->unk2aa) / lbl_803E539C);
}

void bombplantspore_updateDrift(void* obj, void* state)
{
    s16 baseAngle;
    void* params;
    s32 angleDelta;

    params = ((GameObject*)obj)->anim.placementData;
    baseAngle = ((BombplantsporeUpdateDriftPlacement*)params)->unk1C;

    if (randomGetRange(0, 100) < 10 && ((BombPlantSporeState*)state)->unk2a0 <= lbl_803E5394)
    {
        ((BombPlantSporeState*)state)->spinAngle = (s16)randomGetRange(2000, 4000);
        if (randomGetRange(0, 1) != 0)
        {
            ((BombPlantSporeState*)state)->spinAngle = -((BombPlantSporeState*)state)->spinAngle;
        }
        ((BombPlantSporeState*)state)->spinAngle =
            ((BombPlantSporeState*)state)->spinAngle + ((BombPlantSporeState*)state)->unk2a8;
        angleDelta = (s32)((BombPlantSporeState*)state)->spinAngle - (u16)baseAngle;
        if (0x8000 < angleDelta)
        {
            angleDelta -= 0xffff;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta += 0xffff;
        }
        if (((BombplantsporeUpdateDriftPlacement*)params)->unk1A < angleDelta)
        {
            ((BombPlantSporeState*)state)->spinAngle = (s16)(
                baseAngle + ((BombplantsporeUpdateDriftPlacement*)params)->unk1A);
        }
        if (angleDelta < -(s32)((BombplantsporeUpdateDriftPlacement*)params)->unk1A)
        {
            ((BombPlantSporeState*)state)->spinAngle = (s16)(
                baseAngle - ((BombplantsporeUpdateDriftPlacement*)params)->unk1A);
        }
        ((BombPlantSporeState*)state)->unk2a0 = lbl_803E53A8;
    }

    if (randomGetRange(0, 100) < 10 && ((BombPlantSporeState*)state)->unk2a0 <= lbl_803E5394)
    {
        ((BombPlantSporeState*)state)->randomPhase =
            ((BombPlantSporeState*)state)->unk278 + (f32)(int)
        randomGetRange(-200, 200) / lbl_803E5390;
        if (((BombPlantSporeState*)state)->randomPhase < lbl_803E53AC)
        {
            ((BombPlantSporeState*)state)->randomPhase = lbl_803E53AC;
        }
        else if (lbl_803E53B0 < ((BombPlantSporeState*)state)->randomPhase)
        {
            ((BombPlantSporeState*)state)->randomPhase = lbl_803E53B0;
        }
    }

    angleDelta = (s32)((BombPlantSporeState*)state)->spinAngle - (u16)((BombPlantSporeState*)state)->unk2a8;
    if (0x8000 < angleDelta)
    {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xffff;
    }
    ((BombPlantSporeState*)state)->unk2a8 += (s16)((angleDelta * (s32)framesThisStep) >> 4);
    ((BombPlantSporeState*)state)->unk278 =
        lbl_803E53B4 * (((BombPlantSporeState*)state)->randomPhase - ((BombPlantSporeState*)state)->unk278) *
        timeDelta +
        ((BombPlantSporeState*)state)->unk278;

    ((BombPlantSporeState*)state)->driftBaseX =
        ((BombPlantSporeState*)state)->unk278 *
        mathSinf((lbl_803E5398 * (f32)((BombPlantSporeState*)state)->unk2a8) / lbl_803E539C);
    ((BombPlantSporeState*)state)->driftBaseZ =
        ((BombPlantSporeState*)state)->unk278 *
        mathCosf((lbl_803E5398 * (f32)((BombPlantSporeState*)state)->unk2a8) / lbl_803E539C);
}
#pragma dont_inline reset

void bombplant_init(void* obj, void* param, int flag);

#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES 0x66c
#define BOMBPLANTSPORE_MSG_DETONATE 0x7000b
#define BOMBPLANTSPORE_MSG_HIT_PLAYER 0x7000a
#define BOMBPLANTSPORE_PLAYER_DAMAGE_TYPE 0x18e
#define BOMBPLANTSPORE_STATE_FLAG_WAITING_FOR_DETONATE_ACK 0x40
#define BOMBPLANTSPORE_STATE_FLAG_HIT_SURFACE 0x80
#define BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT 10

typedef struct
{
    u8 hitSurface : 1; /* 0x80 */
    u8 waitingAck : 1; /* 0x40 */
    u8 rest : 6;
} BombplantsporeFlags;

void bombplantspore_update(void* obj)
{
    BombPlantSporeState* state;
    s32 particleAlpha;
    s16 hitId;
    void* hitObj;
    int hitObject;
    void* playerObj;
    u32 poppedMessage;
    u32 poppedSender;
    int i;

    state = ((GameObject*)obj)->extra;
    if (((BombplantsporeFlags*)&state->stateFlags)->waitingAck != 0)
    {
        while (ObjMsg_Pop(obj, &poppedMessage, &poppedSender, NULL) != 0)
        {
            switch (poppedMessage)
            {
            case BOMBPLANTSPORE_MSG_DETONATE:
                gameBitIncrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
                Sfx_PlayFromObject(obj, SFXmv_totem_slide);
                (*gExpgfxInterface)->freeSource((u32)obj);
                for (i = 0; i < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; i++)
                {
                    objfx_spawnDirectionalBurst(obj, 5, 7, 1, 0x3c, NULL, 0, lbl_803E53B0, lbl_803E53B8);
                    (*gPartfxInterface)->spawnObject(obj, 0x3f3, NULL, 4, -1, NULL);
                }
                modelLightStruct_setEnabled(state->light, 0, lbl_803E53AC);
                state->detonateTimer = lbl_803E53BC;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject((u32)obj);
                ((BombplantsporeFlags*)&state->stateFlags)->waitingAck = 0;
                break;
            }
        }
        if (((BombplantsporeFlags*)&state->stateFlags)->waitingAck != 0)
        {
            return;
        }
    }

    if (state->detonateTimer != lbl_803E5394)
    {
        *(s16*)obj += (u16)framesThisStep * 0x40;
        state->detonateTimer -= timeDelta;
        if (state->detonateTimer <= lbl_803E5394)
        {
            Obj_FreeObject(obj);
        }
        return;
    }

    if (state->fuseTimer < lbl_803E53C0)
    {
        particleAlpha = (s32) - (lbl_803E53C8 * state->fuseTimer - lbl_803E53C4);
        objfx_spawnDirectionalBurst(obj, 5, 7, 1, particleAlpha & 0xff, NULL, 0, lbl_803E53B0,
                                    (f32)(lbl_803E53D8 *
                                        (double)(lbl_803E53C0 - state->fuseTimer) +
                                        lbl_803E53D0));
    }
    ObjHits_GetPriorityHit((int)obj, &hitObject, 0, 0);
    hitObj = *(void**)((GameObject*)obj)->anim.hitReactState;
    if (((BombplantsporeFlags*)&state->stateFlags)->hitSurface == 0)
    {
        state->driftTimer -= timeDelta;
        if (state->driftTimer < lbl_803E5394)
        {
            state->driftTimer = lbl_803E5394;
        }
        state->unk2a0 -= timeDelta;
        if (state->unk2a0 < lbl_803E5394)
        {
            state->unk2a0 = lbl_803E5394;
        }
        *(s16*)obj += *(u16*)&state->yawStep;
        ((GameObject*)obj)->anim.velocityY = lbl_803E53E0 * timeDelta + ((GameObject*)obj)->anim.velocityY;
        if (lbl_803E53E4 > ((GameObject*)obj)->anim.velocityY)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E53E4;
        }
        if (((GameObject*)obj)->anim.velocityY > lbl_803E5394)
        {
            ((GameObject*)obj)->anim.velocityY *= lbl_803E53E8;
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
        state->spinTimer -= timeDelta;
        if (state->spinTimer <= lbl_803E5394)
        {
            state->driftSin *= lbl_803E53E8;
            state->driftCos *= lbl_803E53E8;
            state->spinTimer = lbl_803E5394;
        }
        else
        {
            state->driftSpeed =
                lbl_803E53EC *
                (state->driftSpeedTarget - state->driftSpeed) *
                timeDelta +
                state->driftSpeed;
        }
        ((GameObject*)obj)->anim.velocityX =
            state->driftSin * state->driftSpeed +
            state->driftBaseX;
        ((GameObject*)obj)->anim.velocityZ =
            state->driftCos * state->driftSpeed +
            state->driftBaseZ;
        objMove(((GameObject*)obj)->anim.velocityX * timeDelta,
                ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta, obj);
        (*gPathControlInterface)->update(obj, (u8*)state + 4, timeDelta);
        (*gPathControlInterface)->apply(obj, (u8*)state + 4);
        (*gPathControlInterface)->advance(obj, (u8*)state + 4, timeDelta);
        if (hitObj != NULL &&
            (hitId = *(s16*)((u8*)hitObj + 0x46), hitId != 0x36d) &&
            hitId != 0x198 && hitId != 0x63c)
        {
            Sfx_PlayFromObject(obj, SFXen_tiles_lightup);
            ((BombplantsporeFlags*)&state->stateFlags)->hitSurface = 1;
            if (lbl_803E53C0 < state->fuseTimer)
            {
                state->fuseTimer = lbl_803E53C0;
            }
        }
        if ((*(u8*)((u8*)state + 0x268) & 0x11) != 0)
        {
            ((BombplantsporeFlags*)&state->stateFlags)->hitSurface = 1;
            if (lbl_803E53C0 < state->fuseTimer)
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
        ((BombplantsporeFlags*)&state->stateFlags)->waitingAck = 1;
    }
    else
    {
        state->fuseTimer -= timeDelta;
        if (state->fuseTimer <= lbl_803E5394)
        {
            Sfx_PlayFromObject(obj, SFXmv_torclp_6);
            (*gExpgfxInterface)->freeSource((u32)obj);
            for (i = 0; i < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; i++)
            {
                objfx_spawnDirectionalBurst(obj, 5, 7, 1, 0x3c, NULL, 0, lbl_803E53B0, lbl_803E53B8);
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
    state->spinAngle = (s16)randomGetRange(0, 0xffff);

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
    state->yawStep = (s16)randomGetRange(-0x200, 0x200);
}

