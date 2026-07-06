/* DLL 0x00FF — magic-gem / collectible objects [80173224-801732A4) */
#include "main/dll_000A_expgfx.h"
#include "main/dll/magicgemstate_struct.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"
#define MAGICGEM_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MAGICGEM_MSG_IN_RANGE               0x7000a /* sent to player when in pickup range */
#define MAGICGEM_MSG_PICKUP                 0x7000b /* collect: award magic + burst */
#define MAGICGEM_GAMEBIT_CLAIMED            0x90d   /* per-frame single-pickup latch */
/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICGEM family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */

extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern u32 ObjMsg_AllocQueue();
extern void ObjLink_DetachChild(int obj, int child);
extern f32 lbl_803E34B0;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void itemPickupDoParticleFx(int obj, f32 scale, int p3, int p4);
extern void playerAddRemoveMagic(int obj, int amount);

extern f32 getXZDistance(f32* a, f32* b);
extern int fn_8029622C(int obj);
extern u8 framesThisStep;
extern char sMagicGemCollectedMessage[];

extern int Obj_GetActiveModel(int obj);
extern u16 lbl_803E34A8;
extern u16 lbl_803E34AC;
extern u8 lbl_80320CB8[];
extern const f32 lbl_803E34E4;
extern const f32 gMagicGemPi;
extern const f32 gMagicGemAngleRandScale;
extern const f32 lbl_803E34F0;
extern const f32 lbl_803E34F4;
extern const f32 lbl_803E34F8;
extern const f32 lbl_803E34FC;
extern f32 timeDelta;
extern const f32 lbl_803E34B4;
extern const f32 gMagicGemActivateDistSq;
extern const f32 gMagicGemVelocityDamping;
extern const f32 gMagicGemGravity;
extern const f32 lbl_803E34C4;
extern const f32 lbl_803E34C8;
extern const f32 gMagicGemBounceSfxSpeed;
extern const f32 gMagicGemFloorNormalThreshold;
extern const f32 gMagicGemBounceRestitutionY;
extern const f32 gMagicGemBounceRestitutionXZ;
extern const f32 gMagicGemPickupYRange;
extern const f32 gMagicGemPickupRadiusBase;
extern int randomGetRange(int lo, int hi);
extern void* Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern f32 sqrtf(f32 x);
extern void objMove(int obj, f32 a, f32 b, f32 c);
STATIC_ASSERT(offsetof(MagicGemState, flags27A) == 0x27A);

void magicgem_free(GameObject* obj)
{
    if (*(u32*)&obj->ownerObj != 0)
    {
        ObjLink_DetachChild(*(int*)&obj->ownerObj, (int)obj);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    return;
}

int magicgem_getExtraSize(void)
{
    return 0x288;
}

void magicgem_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E34B0);
}

void magicgem_update(GameObject* obj)
{
    extern u32 ObjHits_DisableObject(); /* #57 */
    float fval;
    u8 flagsByte;
    int player;
    int ref;
    u32 val;
    MagicGemState* state;
    u8 burstArg;
    char fxArg;
    int msg[1];
    f32 dist;

    player = (int)Obj_GetPlayerObject();
    state = obj->extra;
    while (ref = ObjMsg_Pop(obj, msg, 0x0, 0x0), ref != 0)
    {
        switch (msg[0])
        {
        case MAGICGEM_MSG_PICKUP:
            ref = (int)obj->anim.modelInstance->extraSetupData;
            (*gExpgfxInterface)->freeSource2((u32)obj);
            itemPickupDoParticleFx((int)obj, lbl_803E34B0, state->mode, 0x28);
            ObjHits_DisableObject(obj);
            Sfx_PlayFromObject((int)obj, (u16)state->sfxId);
            Sfx_StopFromObject((int)obj, SFXTRIG_rfall5_c);
            playerAddRemoveMagic(player, (int)*(s8*)(ref + 0xb));
            state->flags27A = state->flags27A & ~5;
            state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECTED;
            state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECT_LATCH;
            state->burstTimer = lbl_803E34B4;
            OSReport(sMagicGemCollectedMessage);
            obj->anim.alpha = 1;
            break;
        }
    }
    if ((state->flags27A & MAGICGEM_FLAG_AMBIENT_FX) == 0)
    {
        if (((state->flags27A & MAGICGEM_FLAG_COLLECT_LATCH) == 0) &&
            (getXZDistance(&obj->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < gMagicGemActivateDistSq))
        {
            state->flags27A = state->flags27A | MAGICGEM_FLAG_AMBIENT_FX;
            fxArg = '\0';
            (*gPartfxInterface)->spawnObject((void*)obj, state->ambientEffectId, NULL, 0x10002, -1, &fxArg);
            fxArg = '\x01';
            (*gPartfxInterface)->spawnObject((void*)obj, state->ambientEffectId, NULL, 0x10002, -1, &fxArg);
            fxArg = '\x02';
            (*gPartfxInterface)->spawnObject((void*)obj, state->ambientEffectId, NULL, 0x10002, -1, &fxArg);
        }
    }
    else
    {
        if (getXZDistance(&obj->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) >= gMagicGemActivateDistSq)
        {
            state->flags27A = state->flags27A & ~MAGICGEM_FLAG_AMBIENT_FX;
            (*gExpgfxInterface)->freeSource2((u32)obj);
        }
    }
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        if ((state->flags27A & MAGICGEM_FLAG_SETTLED) != 0)
        {
            obj->anim.rotX = obj->anim.rotX + framesThisStep * 0x100;
            if ((state->ambientTimer -= framesThisStep) < 0)
            {
                Sfx_PlayFromObject((int)obj, SFXen_statue_wave);
                val = randomGetRange(0xf0, 300);
                state->ambientTimer = val;
            }
        }
        if (*(u32*)&obj->ownerObj != 0)
        {
            player = (int)obj->anim.modelState;
            if ((u32)player != 0)
            {
                obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
            (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
            goto LAB_80173f80;
        }
        ref = (int)obj->anim.modelState;
        if ((u32)ref != 0)
        {
            /* the long-long mask is load-bearing: ~0x1000LL clears
               OBJ_MODEL_STATE_SHADOW_FADE_OUT via a 64-bit constant, which the
               named 32-bit define does not reproduce. */
            obj->anim.modelState->flags &= ~0x1000LL;
        }
        state->unk25B = 1;
        if ((state->flags27A & 3) == 0)
        {
            obj->anim.velocityX = obj->anim.velocityX * gMagicGemVelocityDamping;
            obj->anim.velocityZ = obj->anim.velocityZ * gMagicGemVelocityDamping;
            obj->anim.velocityY = -(gMagicGemGravity * timeDelta - obj->anim.velocityY);
        }
        state->burstTimer = state->burstTimer - timeDelta;
        flagsByte = state->flags27A;
        if ((flagsByte & MAGICGEM_FLAG_BURST1) != 0)
        {
            if (state->burstTimer <= lbl_803E34C4)
            {
                state->flags27A = flagsByte & ~MAGICGEM_FLAG_BURST1;
                state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST2;
                state->burstTimer = lbl_803E34C8;
                obj->anim.alpha = 0xff;
            }
            if (obj->anim.parent == NULL)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, state->burstEffectId, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, state->burstEffectId, NULL, 1, -1, NULL);
            }
        }
        else
        {
            if ((flagsByte & MAGICGEM_FLAG_BURST2) != 0)
            {
                if (state->burstTimer <= lbl_803E34C4)
                {
                    state->flags27A = flagsByte & ~MAGICGEM_FLAG_BURST2;
                    state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECTED;
                    state->burstTimer = lbl_803E34B4;
                    (*gExpgfxInterface)->freeSource2((u32)obj);
                    if (obj->anim.parent == NULL)
                    {
                        for (burstArg = '\x1e'; burstArg != '\0'; burstArg--)
                        {
                            (*gPartfxInterface)->spawnObject((void*)obj, state->burstEffectId, NULL, 1, -1, &burstArg);
                        }
                    }
                    obj->anim.alpha = 1;
                    Sfx_PlayFromObject((int)obj, SFXen_waterblock_wave);
                }
                objMove((int)obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                        obj->anim.velocityZ * timeDelta);
            }
            else
            {
                if (state->burstTimer <= lbl_803E34C4)
                {
                    Obj_FreeObject((int)obj);
                }
                goto LAB_80173f80;
            }
        }
        if ((state->flags27A & 3) == 0)
        {
            (*gPathControlInterface)->update((void*)obj, (void*)state, timeDelta);
            (*gPathControlInterface)->apply((void*)obj, (void*)state);
            (*gPathControlInterface)->advance((void*)obj, (void*)state, timeDelta);
            if (state->unk261 != '\0')
            {
                float vx = -obj->anim.velocityX;
                float vy = -obj->anim.velocityY;
                float vz = -obj->anim.velocityZ;
                float mag = sqrtf(vx * vx + vy * vy + vz * vz);
                if (mag > gMagicGemBounceSfxSpeed)
                {
                    Sfx_PlayFromObject((int)obj, SFXwp_iceywindlp16);
                }
                if (state->unk6C >= gMagicGemFloorNormalThreshold)
                {
                    obj->anim.velocityY = -obj->anim.velocityY;
                    obj->anim.velocityY = obj->anim.velocityY * gMagicGemBounceRestitutionY;
                }
                else
                {
                    obj->anim.velocityX = -obj->anim.velocityX;
                    obj->anim.velocityZ = -obj->anim.velocityZ;
                    obj->anim.velocityX = obj->anim.velocityX * gMagicGemBounceRestitutionXZ;
                    obj->anim.velocityZ = obj->anim.velocityZ * gMagicGemBounceRestitutionXZ;
                }
                ref = state->bounceCount + 1;
                state->bounceCount++;
                if (5 < (u8)ref)
                {
                    state->flags27A = state->flags27A | MAGICGEM_FLAG_SETTLED;
                    fval = lbl_803E34C4;
                    obj->anim.velocityX = lbl_803E34C4;
                    obj->anim.velocityY = fval;
                    obj->anim.velocityZ = fval;
                }
            }
        }
    }
    if (((state->flags27A & MAGICGEM_FLAG_CLAIMED) == 0) && ((state->flags27A & MAGICGEM_FLAG_COLLECT_LATCH) == 0))
    {
        fval = obj->anim.localPosY - ((GameObject*)player)->anim.localPosY;
        if (fval < lbl_803E34C4)
        {
            fval = -fval;
        }
        if (fval < gMagicGemPickupYRange)
        {
            dist = getXZDistance(&obj->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
            fval = gMagicGemPickupRadiusBase + state->collectRadius;
            if ((dist < fval * fval) && (fn_8029622C(player) != 0))
            {
                val = GameBit_Get(MAGICGEM_GAMEBIT_CLAIMED);
                if (val == 0)
                {
                    /* s16 store is load-bearing: writing 0xffff through the s16 view
                       differs in codegen from a plain u16 field store. */
                    *(s16*)&state->pickupMsgArg = 0xffff;
                    ObjMsg_SendToObject(player, MAGICGEM_MSG_IN_RANGE, obj, (int)state + 0x280);
                    ObjHits_DisableObject(obj);
                    GameBit_Set(MAGICGEM_GAMEBIT_CLAIMED, 1);
                    state->flags27A = state->flags27A | MAGICGEM_FLAG_CLAIMED;
                }
                else
                {
                    ref = (int)obj->anim.modelInstance->extraSetupData;
                    (*gExpgfxInterface)->freeSource2((u32)obj);
                    itemPickupDoParticleFx((int)obj, lbl_803E34B0, state->mode, 0x28);
                    ObjHits_DisableObject(obj);
                    Sfx_PlayFromObject((int)obj, (u16)state->sfxId);
                    Sfx_StopFromObject((int)obj, SFXTRIG_rfall5_c);
                    playerAddRemoveMagic(player, (int)*(s8*)(ref + 0xb));
                    state->flags27A = state->flags27A & ~5;
                    state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECTED;
                    state->flags27A = state->flags27A | MAGICGEM_FLAG_COLLECT_LATCH;
                    state->burstTimer = lbl_803E34B4;
                    OSReport(sMagicGemCollectedMessage);
                    obj->anim.alpha = 1;
                }
            }
        }
    }
LAB_80173f80:
    return;
}

typedef struct MagicgemObjectDef
{
    u8 pad0[0x26 - 0x0];
    u8 bankIndex;
    u8 pad27[0x2e - 0x27];
    s16 spawnMode;
} MagicgemObjectDef;

void magicgem_init(GameObject* obj, MagicgemObjectDef* placement)
{
    extern u32 ObjHits_DisableObject(); /* #57 */
    short mode;
    u32 randVal;
    int ref;
    MagicGemState* state;
    f32 ang;
    f32 spd;
    u16 texPickA[2];
    u16 texPickB[2];
    u8 pathArgs[4];

    state = obj->extra;
    pathArgs[0] = 3;
    texPickA[0] = lbl_803E34A8;
    texPickB[0] = lbl_803E34AC;
    randVal = randomGetRange(0, 0xffff);
    spd = (f32)(int)randomGetRange(0x27, 0x2c) / lbl_803E34E4;
    ang = (gMagicGemPi * (f32)(int)randVal) / gMagicGemAngleRandScale;
    obj->anim.velocityX = spd * mathSinf(ang);
    obj->anim.velocityZ = spd * mathCosf(ang);
    obj->anim.velocityY = (f32)(int)randomGetRange(0x28, 0x32) / lbl_803E34F0;
    mode = placement->spawnMode;
    if (mode == 1)
    {
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = 1;
    }
    else if (mode == 2)
    {
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = 1;
        if (*(u32*)&obj->anim.hitReactState != 0)
        {
            ObjHits_DisableObject(obj);
        }
        ref = (int)Obj_GetPlayerObject();
        obj->anim.velocityX = (((GameObject*)ref)->anim.localPosX - obj->anim.localPosX) / lbl_803E34F4;
        obj->anim.velocityY = (((GameObject*)ref)->anim.localPosY - obj->anim.localPosY) / lbl_803E34F4;
        obj->anim.velocityZ = (((GameObject*)ref)->anim.localPosZ - obj->anim.localPosZ) / lbl_803E34F4;
    }
    else if (mode == 3)
    {
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST1;
        obj->anim.alpha = 1;
        obj->anim.velocityY = -((f32)(int)randomGetRange(0x8c, 0x96) / lbl_803E34F0);
    }
    obj->anim.bankIndex = placement->bankIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount)
    {
        obj->anim.bankIndex = 0;
    }
    if (obj->anim.modelState != NULL)
    {
        obj->anim.modelState->shadowTintA = 100;
        obj->anim.modelState->shadowTintB = 0x96;
    }
    ref = Obj_GetActiveModel((int)obj);
    mode = obj->anim.seqId;
    switch (mode)
    {
    case 0x2c4:
        randVal = randomGetRange(0, 1);
        *(u8*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickA + randVal);
        state->ambientEffectId = 0x54f;
        state->burstEffectId = 0x54b;
        state->sfxId = 0x58;
        state->unk276 = 0x5b0;
        state->mode = 4;
        break;
    case 0x2cd:
        randVal = randomGetRange(0, 1);
        *(u8*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickB + randVal);
        state->ambientEffectId = 0x54e;
        state->burstEffectId = 0x54a;
        state->sfxId = 0x59;
        state->unk276 = 0x5b1;
        state->mode = 1;
        break;
    case 0x2ce:
        *(u8*)(*(int*)(ref + 0x34) + 8) = 3;
        state->ambientEffectId = 0x54d;
        state->burstEffectId = 0x549;
        state->sfxId = 0x5a;
        state->unk276 = 0x5b2;
        state->mode = 2;
        break;
    case 0x2cf:
    default:
        *(u8*)(*(int*)(ref + 0x34) + 8) = 2;
        state->ambientEffectId = 0x550;
        state->burstEffectId = 0x54c;
        state->sfxId = 0x5b;
        state->unk276 = 0x5b3;
        state->mode = 6;
        break;
    }
    state->collectRadius = lbl_803E34F8;
    if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        (*gPathControlInterface)->init((void*)state, 0, 0x40007, 0);
        (*gPathControlInterface)->setup((void*)state, 1, lbl_80320CB8, (void*)((int)state + 0x268), pathArgs);
        (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
    }
    obj->objectFlags = obj->objectFlags | MAGICGEM_OBJFLAG_HITDETECT_DISABLED;
    if ((state->flags27A & MAGICGEM_FLAG_BURST1) != 0)
    {
        state->burstTimer = lbl_803E34FC;
    }
    else
    {
        state->burstTimer = lbl_803E34C8;
        state->flags27A = state->flags27A | MAGICGEM_FLAG_BURST2;
    }
    ObjMsg_AllocQueue(obj, 1);
    return;
}

char sMagicGemCollectedMessage[] = "Magic collected";
