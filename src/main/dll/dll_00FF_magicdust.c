/* DLL 0x00FF — magic-dust / collectible objects [80173224-801732A4) */
#include "main/dll_000A_expgfx.h"
#include "main/dll/magicduststate_struct.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"
#define MAGICDUST_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MAGICDUST_MSG_IN_RANGE 0x7000a    /* sent to player when in pickup range */
#define MAGICDUST_MSG_PICKUP 0x7000b      /* collect: award magic + burst */
#define MAGICDUST_GAMEBIT_CLAIMED 0x90d   /* per-frame single-pickup latch */
/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICDUST family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */

extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern u32 ObjMsg_AllocQueue();
extern void ObjLink_DetachChild(int obj, int child);
extern f32 lbl_803E34B0;
extern void objRenderFn_8003b8f4(f32);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void itemPickupDoParticleFx(int obj, f32 scale, int p3, int p4);
extern void playerAddRemoveMagic(int obj, int amount);

extern f32 getXZDistance(f32* a, f32* b);
extern int fn_8029622C(int obj);
extern u8 framesThisStep;
extern char sMagicDustCollectedMessage[];


extern int Obj_GetActiveModel(int obj);
extern u16 lbl_803E34A8;
extern u16 lbl_803E34AC;
extern u8 lbl_80320CB8[];
extern const f32 lbl_803E34E4;
extern const f32 gMagicDustPi;
extern const f32 gMagicDustAngleRandScale;
extern const f32 lbl_803E34F0;
extern const f32 lbl_803E34F4;
extern const f32 lbl_803E34F8;
extern const f32 lbl_803E34FC;
extern f32 timeDelta;
extern const f32 lbl_803E34B4;
extern const f32 gMagicDustActivateDistSq;
extern const f32 lbl_803E34BC;
extern const f32 gMagicDustGravity;
extern const f32 lbl_803E34C4;
extern const f32 lbl_803E34C8;
extern const f32 lbl_803E34CC;
extern const f32 lbl_803E34D0;
extern const f32 lbl_803E34D4;
extern const f32 lbl_803E34D8;
extern const f32 lbl_803E34DC;
extern const f32 lbl_803E34E0;
extern int randomGetRange(int lo, int hi);
extern void* Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern f32 sqrtf(f32 x);
extern void objMove(int obj, f32 a, f32 b, f32 c);
STATIC_ASSERT(offsetof(MagicDustState, flags27A) == 0x27A);

void magicdust_free(int obj)
{
    if (*(u32*)(obj + 0xc4) != 0)
    {
        ObjLink_DetachChild(*(int*)(obj + 0xc4), obj);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    return;
}

int magicdust_getExtraSize(void) { return 0x288; }

void magicdust_render(void) { objRenderFn_8003b8f4(lbl_803E34B0); }

#pragma opt_loop_invariants off
void magicdust_update(int obj)
{
    extern u32 ObjHits_DisableObject(); /* #57 */
    float fval;
    u8 flagsByte;
    int player;
    int ref;
    u32 val;
    int state;
    u8 burstArg;
    char fxArg;
    int msg[1];
    f32 dist;

    player = (int)Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;
    while (ref = ObjMsg_Pop(obj, msg, 0x0, 0x0), ref != 0)
    {
        switch (msg[0])
        {
        case MAGICDUST_MSG_PICKUP:
            ref = (int)((GameObject*)obj)->anim.modelInstance->extraSetupData;
            (*gExpgfxInterface)->freeSource2((u32)obj);
            itemPickupDoParticleFx(obj, lbl_803E34B0, ((MagicDustState*)state)->mode, 0x28);
            ObjHits_DisableObject(obj);
            Sfx_PlayFromObject(obj, (u16)((MagicDustState*)state)->sfxId);
            Sfx_StopFromObject(obj, SFXTRIG_rfall5_c);
            playerAddRemoveMagic(player, (int)*(s8*)(ref + 0xb));
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A & ~5;
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 8;
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 0x40;
            ((MagicDustState*)state)->burstTimer = lbl_803E34B4;
            OSReport(sMagicDustCollectedMessage);
            ((GameObject*)obj)->anim.alpha = 1;
            break;
        }
    }
    if ((((MagicDustState*)state)->flags27A & 0x10) == 0)
    {
        if (((((MagicDustState*)state)->flags27A & 0x40) == 0) &&
            (getXZDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < gMagicDustActivateDistSq))
        {
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 0x10;
            fxArg = '\0';
            (*gPartfxInterface)->spawnObject((void*)obj,
                                             ((MagicDustState*)state)->ambientEffectId, NULL, 0x10002, -1, &fxArg);
            fxArg = '\x01';
            (*gPartfxInterface)->spawnObject((void*)obj,
                                             ((MagicDustState*)state)->ambientEffectId, NULL, 0x10002, -1, &fxArg);
            fxArg = '\x02';
            (*gPartfxInterface)->spawnObject((void*)obj,
                                             ((MagicDustState*)state)->ambientEffectId, NULL, 0x10002, -1, &fxArg);
        }
    }
    else
    {
        if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) >= gMagicDustActivateDistSq)
        {
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A & ~0x10;
            (*gExpgfxInterface)->freeSource2((u32)obj);
        }
    }
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        if ((((MagicDustState*)state)->flags27A & 2) != 0)
        {
            *(short*)obj = *(short*)obj + framesThisStep * 0x100;
            if ((((MagicDustState*)state)->ambientTimer -= framesThisStep) < 0)
            {
                Sfx_PlayFromObject(obj, SFXen_statue_wave);
                val = randomGetRange(0xf0, 300);
                ((MagicDustState*)state)->ambientTimer = val;
            }
        }
        if (*(u32*)&((GameObject*)obj)->ownerObj != 0)
        {
            player = (int)((GameObject*)obj)->anim.modelState;
            if ((u32)player != 0)
            {
                ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
            (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
            goto LAB_80173f80;
        }
        ref = (int)((GameObject*)obj)->anim.modelState;
        if ((u32)ref != 0)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~0x1000LL;
        }
        *(u8*)&((MagicDustState*)state)->unk25B = 1;
        if ((((MagicDustState*)state)->flags27A & 3) == 0)
        {
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * lbl_803E34BC;
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * lbl_803E34BC;
            ((GameObject*)obj)->anim.velocityY = -(gMagicDustGravity * timeDelta - ((GameObject*)obj)->anim.velocityY);
        }
        ((MagicDustState*)state)->burstTimer = ((MagicDustState*)state)->burstTimer - timeDelta;
        flagsByte = ((MagicDustState*)state)->flags27A;
        if ((flagsByte & 1) != 0)
        {
            if (((MagicDustState*)state)->burstTimer <= lbl_803E34C4)
            {
                ((MagicDustState*)state)->flags27A = flagsByte & ~1;
                ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 4;
                ((MagicDustState*)state)->burstTimer = lbl_803E34C8;
                ((GameObject*)obj)->anim.alpha = 0xff;
            }
            if (*(void**)&((GameObject*)obj)->anim.parent == NULL)
            {
                (*gPartfxInterface)->spawnObject((void*)obj,
                                                 ((MagicDustState*)state)->burstEffectId, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj,
                                                 ((MagicDustState*)state)->burstEffectId, NULL, 1, -1, NULL);
            }
        }
        else
        {
            if ((flagsByte & 4) != 0)
            {
                if (((MagicDustState*)state)->burstTimer <= lbl_803E34C4)
                {
                    ((MagicDustState*)state)->flags27A = flagsByte & ~4;
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 8;
                    ((MagicDustState*)state)->burstTimer = lbl_803E34B4;
                    (*gExpgfxInterface)->freeSource2((u32)obj);
                    if (*(void**)&((GameObject*)obj)->anim.parent == NULL)
                    {
                        for (burstArg = '\x1e'; burstArg != '\0'; burstArg--)
                        {
                            (*gPartfxInterface)->spawnObject((void*)obj,
                                                             ((MagicDustState*)state)->burstEffectId, NULL, 1, -1,
                                                             &burstArg);
                        }
                    }
                    ((GameObject*)obj)->anim.alpha = 1;
                    Sfx_PlayFromObject(obj, SFXen_waterblock_wave);
                }
                objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                        ((GameObject*)obj)->anim.velocityZ * timeDelta);
            }
            else
            {
                if (((MagicDustState*)state)->burstTimer <= lbl_803E34C4)
                {
                    Obj_FreeObject(obj);
                }
                goto LAB_80173f80;
            }
        }
        if ((((MagicDustState*)state)->flags27A & 3) == 0)
        {
            (*gPathControlInterface)->update((void*)obj, (void*)state, timeDelta);
            (*gPathControlInterface)->apply((void*)obj, (void*)state);
            (*gPathControlInterface)->advance((void*)obj, (void*)state, timeDelta);
            if (((MagicDustState*)state)->unk261 != '\0')
            {
                float vx = -((GameObject*)obj)->anim.velocityX;
                float vy = -((GameObject*)obj)->anim.velocityY;
                float vz = -((GameObject*)obj)->anim.velocityZ;
                float mag = sqrtf(vx * vx + vy * vy + vz * vz);
                if (mag > lbl_803E34CC)
                {
                    Sfx_PlayFromObject(obj, SFXwp_iceywindlp16);
                }
                if (((MagicDustState*)state)->unk6C >= lbl_803E34D0)
                {
                    ((GameObject*)obj)->anim.velocityY = -((GameObject*)obj)->anim.velocityY;
                    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803E34D4;
                }
                else
                {
                    ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityX;
                    ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityZ;
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * lbl_803E34D8;
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * lbl_803E34D8;
                }
                ref = ((MagicDustState*)state)->bounceCount + 1;
                ((MagicDustState*)state)->bounceCount++;
                if (5 < (u8)ref)
                {
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 2;
                    fval = lbl_803E34C4;
                    ((GameObject*)obj)->anim.velocityX = lbl_803E34C4;
                    ((GameObject*)obj)->anim.velocityY = fval;
                    ((GameObject*)obj)->anim.velocityZ = fval;
                }
            }
        }
    }
    if (((((MagicDustState*)state)->flags27A & 0x20) == 0) && ((((MagicDustState*)state)->flags27A & 0x40) == 0))
    {
        fval = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
        if (fval < lbl_803E34C4)
        {
            fval = -fval;
        }
        if (fval < lbl_803E34DC)
        {
            dist = getXZDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
            fval = lbl_803E34E0 + ((MagicDustState*)state)->collectRadius;
            if ((dist < fval * fval) && (fn_8029622C(player) != 0))
            {
                val = GameBit_Get(MAGICDUST_GAMEBIT_CLAIMED);
                if (val == 0)
                {
                    *(s16*)&((MagicDustState*)state)->pickupMsgArg = 0xffff;
                    ObjMsg_SendToObject(player, MAGICDUST_MSG_IN_RANGE, obj, state + 0x280);
                    ObjHits_DisableObject(obj);
                    GameBit_Set(MAGICDUST_GAMEBIT_CLAIMED, 1);
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 0x20;
                }
                else
                {
                    ref = (int)((GameObject*)obj)->anim.modelInstance->extraSetupData;
                    (*gExpgfxInterface)->freeSource2((u32)obj);
                    itemPickupDoParticleFx(obj, lbl_803E34B0, ((MagicDustState*)state)->mode, 0x28);
                    ObjHits_DisableObject(obj);
                    Sfx_PlayFromObject(obj, (u16)((MagicDustState*)state)->sfxId);
                    Sfx_StopFromObject(obj, SFXTRIG_rfall5_c);
                    playerAddRemoveMagic(player, (int)*(s8*)(ref + 0xb));
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A & ~5;
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 8;
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 0x40;
                    ((MagicDustState*)state)->burstTimer = lbl_803E34B4;
                    OSReport(sMagicDustCollectedMessage);
                    ((GameObject*)obj)->anim.alpha = 1;
                }
            }
        }
    }
LAB_80173f80:
    return;
}
#pragma opt_loop_invariants reset

typedef struct MagicdustObjectDef
{
    u8 pad0[0x26 - 0x0];
    u8 bankIndex;
    u8 pad27[0x2e - 0x27];
    s16 spawnMode;
} MagicdustObjectDef;

void magicdust_init(int obj, int placement)
{
    extern u32 ObjHits_DisableObject(); /* #57 */
    short mode;
    float chaseTime;
    u32 randVal;
    int ref;
    int state;
    f32 ang;
    f32 spd;
    u16 texPickA[2];
    u16 texPickB[2];
    u8 pathArgs[4];
    u32 convHi0;
    u32 convLo0;
    u32 convHi1;
    u32 convLo1;
    u32 convHi2;
    u32 convLo2;

    state = *(int*)&((GameObject*)obj)->extra;
    pathArgs[0] = 3;
    texPickA[0] = lbl_803E34A8;
    texPickB[0] = lbl_803E34AC;
    randVal = randomGetRange(0, 0xffff);
    spd = (f32)(int)
    randomGetRange(0x27, 0x2c) / lbl_803E34E4;
    ang = (gMagicDustPi * (f32)(int)
    randVal
    )
    /
    gMagicDustAngleRandScale;
    ((GameObject*)obj)->anim.velocityX = spd * mathSinf(ang);
    ((GameObject*)obj)->anim.velocityZ = spd * mathCosf(ang);
    ((GameObject*)obj)->anim.velocityY = (f32)(int)
    randomGetRange(0x28, 0x32) / lbl_803E34F0;
    mode = ((MagicdustObjectDef*)placement)->spawnMode;
    if (mode == 1)
    {
        ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 1;
        ((GameObject*)obj)->anim.alpha = 1;
    }
    else if (mode == 2)
    {
        ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 1;
        ((GameObject*)obj)->anim.alpha = 1;
        if (*(u32*)&((GameObject*)obj)->anim.hitReactState != 0)
        {
            ObjHits_DisableObject(obj);
        }
        ref = (int)Obj_GetPlayerObject();
        ((GameObject*)obj)->anim.velocityX =
            (((GameObject*)ref)->anim.localPosX - ((GameObject*)obj)->anim.localPosX) / lbl_803E34F4;
        ((GameObject*)obj)->anim.velocityY = (((GameObject*)ref)->anim.localPosY - ((GameObject*)obj)->anim.localPosY) / lbl_803E34F4;
        ((GameObject*)obj)->anim.velocityZ = (((GameObject*)ref)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ) / lbl_803E34F4;
    }
    else if (mode == 3)
    {
        ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 1;
        ((GameObject*)obj)->anim.alpha = 1;
        ((GameObject*)obj)->anim.velocityY =
            -((f32)(int)
        randomGetRange(0x8c, 0x96) / lbl_803E34F0
        )
        ;
    }
    ((ObjAnimComponent*)obj)->bankIndex = ((MagicdustObjectDef*)placement)->bankIndex;
    if (((ObjAnimComponent*)obj)->bankIndex >=
        ((ObjAnimComponent*)obj)->modelInstance->modelCount)
    {
        ((ObjAnimComponent*)obj)->bankIndex = 0;
    }
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->shadowTintA = 100;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
    }
    ref = Obj_GetActiveModel(obj);
    mode = ((GameObject*)obj)->anim.seqId;
    switch (mode)
    {
    case 0x2c4:
        randVal = randomGetRange(0, 1);
        *(u8*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickA + randVal);
        *(u16*)&((MagicDustState*)state)->ambientEffectId = 0x54f;
        *(u16*)&((MagicDustState*)state)->burstEffectId = 0x54b;
        *(u16*)&((MagicDustState*)state)->sfxId = 0x58;
        *(u16*)&((MagicDustState*)state)->unk276 = 0x5b0;
        *(u8*)&((MagicDustState*)state)->mode = 4;
        break;
    case 0x2cd:
        randVal = randomGetRange(0, 1);
        *(u8*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickB + randVal);
        *(u16*)&((MagicDustState*)state)->ambientEffectId = 0x54e;
        *(u16*)&((MagicDustState*)state)->burstEffectId = 0x54a;
        *(u16*)&((MagicDustState*)state)->sfxId = 0x59;
        *(u16*)&((MagicDustState*)state)->unk276 = 0x5b1;
        *(u8*)&((MagicDustState*)state)->mode = 1;
        break;
    case 0x2ce:
        *(u8*)(*(int*)(ref + 0x34) + 8) = 3;
        *(u16*)&((MagicDustState*)state)->ambientEffectId = 0x54d;
        *(u16*)&((MagicDustState*)state)->burstEffectId = 0x549;
        *(u16*)&((MagicDustState*)state)->sfxId = 0x5a;
        *(u16*)&((MagicDustState*)state)->unk276 = 0x5b2;
        *(u8*)&((MagicDustState*)state)->mode = 2;
        break;
    case 0x2cf:
    default:
        *(u8*)(*(int*)(ref + 0x34) + 8) = 2;
        *(u16*)&((MagicDustState*)state)->ambientEffectId = 0x550;
        *(u16*)&((MagicDustState*)state)->burstEffectId = 0x54c;
        *(u16*)&((MagicDustState*)state)->sfxId = 0x5b;
        *(u16*)&((MagicDustState*)state)->unk276 = 0x5b3;
        *(u8*)&((MagicDustState*)state)->mode = 6;
        break;
    }
    ((MagicDustState*)state)->collectRadius = lbl_803E34F8;
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        (*gPathControlInterface)->init((void*)state, 0, 0x40007, 0);
        (*gPathControlInterface)->setup((void*)state, 1, lbl_80320CB8, (void*)(state + 0x268), pathArgs);
        (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
    }
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | MAGICDUST_OBJFLAG_HITDETECT_DISABLED;
    if ((((MagicDustState*)state)->flags27A & 1) != 0)
    {
        ((MagicDustState*)state)->burstTimer = lbl_803E34FC;
    }
    else
    {
        ((MagicDustState*)state)->burstTimer = lbl_803E34C8;
        ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 4;
    }
    ObjMsg_AllocQueue(obj, 1);
    return;
}

char sMagicDustCollectedMessage[] = "Magic collected";
