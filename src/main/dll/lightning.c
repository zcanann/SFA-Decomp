/* === moved from main/dll/texframeanimator.c [80173224-801732A4) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/texframeanimator.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICDUST family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */
#include "main/game_object.h"
#include "main/dll/collectible_state.h"
#include "main/dll/gfxEmit.h"
#include "main/dll/path_control_interface.h"
#include "main/objanim_internal.h"

extern uint GameBit_Get(int eventId);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 ObjLink_DetachChild();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801713ac();
extern uint countLeadingZeros();

extern undefined4 DAT_803218a8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803e40d8;
extern undefined4 DAT_803e40dc;
extern f64 DOUBLE_803e40e0;
extern f32 lbl_803DC074;
extern f32 lbl_803E40E8;
extern f32 lbl_803E40EC;
extern f32 lbl_803E40F0;
extern f32 lbl_803E40F4;
extern f32 lbl_803E412C;
extern f32 lbl_803E4130;
extern f32 lbl_803E4134;
extern f32 lbl_803E4138;
extern u8 lbl_80320C58[];
extern u32 lbl_803E3440;
extern u8 lbl_803E3444;
extern f32 lbl_803E345C;
extern f32 lbl_803E3494;
extern f32 lbl_803E3498;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;

/*
 * --INFO--
 *
 * Function: collectible_init
 * EN v1.0 Address: 0x80172F14
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: 0x801730D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


void magicdust_free(int param_1)
{
    if (*(uint*)(param_1 + 0xc4) != 0)
    {
        ObjLink_DetachChild(*(int*)(param_1 + 0xc4), param_1);
    }
    (*gExpgfxInterface)->freeSource2((u32)param_1);
    return;
}


/*
 * --INFO--
 *
 * Function: collectible_release
 * EN v1.0 Address: 0x8017321C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80173378
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: collectible_initialise
 * EN v1.0 Address: 0x80173220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017337C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* 8b "li r3, N; blr" returners. */
int magicdust_getExtraSize(void) { return 0x288; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E34B0;
extern void objRenderFn_8003b8f4(f32);
void magicdust_render(void) { objRenderFn_8003b8f4(lbl_803E34B0); }

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/obj_placement.h"
#include "main/dll/lightning.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/pushable.h"
#include "main/objanim_internal.h"
#include "main/game_object.h"
#include "main/resource.h"

typedef struct EffectboxPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 rotYaw;
    u8 rotPitch;
    u8 extentX;
    u8 extentY;
    u8 extentZ;
    u8 unk1D;
    u8 pad1E[0x1F - 0x1E];
    u8 gameBitValue;
    s16 unk20;
    u8 targetMode;
    u8 pad23[0x28 - 0x23];
} EffectboxPlacement;


extern int Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void itemPickupDoParticleFx(int obj, f32 scale, int p3, int p4);
extern void playerAddRemoveMagic(int player, int amount);
extern void OSReport(const char* fmt, ...);
extern f32 getXZDistance(void* a, void* b);
extern int fn_8029622C(int player);
extern u8 framesThisStep;
extern char sMagicDustCollectedMessage[];
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern int Obj_GetActiveModel(int obj);
extern u16 lbl_803E34A8;
extern u16 lbl_803E34AC;
extern u8 lbl_80320CB8[];
extern f32 lbl_803E34E4;
extern f32 lbl_803E34E8;
extern f32 lbl_803E34EC;
extern f32 lbl_803E34F0;
extern f32 lbl_803E34F4;
extern f32 lbl_803E34F8;
extern f32 lbl_803E34FC;
extern EffectInterface** gPartfxInterface;
extern f32 timeDelta;
extern f32 lbl_803E34B4;
extern f32 lbl_803E34B8;
extern f32 lbl_803E34BC;
extern f32 lbl_803E34C0;
extern f32 lbl_803E34C4;
extern f32 lbl_803E34C8;
extern f32 lbl_803E34CC;
extern f32 lbl_803E34D0;
extern f32 lbl_803E34D4;
extern f32 lbl_803E34D8;
extern f32 lbl_803E34DC;
extern f32 lbl_803E34E0;
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern void* ObjGroup_GetObjects();
extern undefined4 fn_80174BFC();
extern u8* Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern f32 sqrtf(f32 x);
extern void objMove(f32 a, f32 b, f32 c, int obj);

extern f64 DOUBLE_803e4198;
extern f64 DOUBLE_803e41b0;
extern f64 DOUBLE_803e41b8;
extern f64 DOUBLE_803e41c8;
extern f64 DOUBLE_803e41d0;
extern f32 lbl_803E4148;
extern f32 lbl_803E414C;
extern f32 lbl_803E4150;
extern f32 lbl_803E4154;
extern f32 lbl_803E4158;
extern f32 lbl_803E415C;
extern f32 lbl_803E4160;
extern f32 lbl_803E4164;
extern f32 lbl_803E4168;
extern f32 lbl_803E416C;
extern f32 lbl_803E4170;
extern f32 lbl_803E4174;
extern f32 lbl_803E4178;
extern f32 lbl_803E417C;
extern f32 lbl_803E4188;
extern f32 lbl_803E418C;
extern f32 lbl_803E4190;
extern f32 lbl_803E4194;
extern f32 lbl_803E41AC;
extern f32 lbl_803E41C4;

/* magicdust extra block (collectible sparkle state; tail of the pickup record). */
typedef struct MagicDustState
{
    u8 unk00[0x6C];
    f32 unk6C;
    u8 unk70[0x25B - 0x70];
    u8 unk25B;
    u8 unk25C[5];
    s8 unk261;
    u8 unk262[6];
    f32 unk268;
    f32 burstTimer; /* counts down to the next 30-particle burst */
    u16 burstEffectId;
    u16 ambientEffectId; /* partfx effect id */
    s16 sfxId; /* collect sfx id */
    s16 unk276;
    s16 ambientTimer;
    u8 flags27A; /* bits 8/0x10/0x40 observed; &0xFA clear on collect */
    u8 bounceCount;
    u8 mode; /* particle color row */
    u8 unk27D[3];
    u16 unk280;
} MagicDustState;

STATIC_ASSERT(offsetof(MagicDustState, flags27A) == 0x27A);

/*
 * --INFO--
 *
 * Function: magicdust_update
 * EN v1.0 Address: 0x801732A4
 * EN v1.0 Size: 2272b
 * EN v1.1 Address: 0x80173750
 * EN v1.1 Size: 2120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void magicdust_update(int obj)
{
    extern undefined4 ObjHits_DisableObject(); /* #57 */
    float fval;
    short sVar2;
    byte byteVal;
    int player;
    int ref;
    uint val;
    int state;
    double dVar9;
    char fxArg;
    char burstArg[3];
    int msg[9];
    register int msgId;
    f32 dist;

    player = (int)Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;
    msgId = 0x7000b;
    while (ref = ObjMsg_Pop(obj, (uint*)msg, (uint*)0x0, (uint*)0x0), ref != 0)
    {
        if (msg[0] == msgId)
        {
            ref = *(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x18);
            (*gExpgfxInterface)->freeSource2((u32)obj);
            itemPickupDoParticleFx(obj, lbl_803E34B0, ((MagicDustState*)state)->mode, 0x28);
            ObjHits_DisableObject(obj);
            Sfx_PlayFromObject(obj, (u16)((MagicDustState*)state)->sfxId);
            Sfx_StopFromObject(obj, 0x56);
            playerAddRemoveMagic(player, (int)*(s8*)(ref + 0xb));
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A & 0xfa;
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 8;
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 0x40;
            ((MagicDustState*)state)->burstTimer = lbl_803E34B4;
            OSReport(sMagicDustCollectedMessage);
            ((GameObject*)obj)->anim.alpha = 1;
        }
    }
    if ((((MagicDustState*)state)->flags27A & 0x10) == 0)
    {
        if (((((MagicDustState*)state)->flags27A & 0x40) == 0) &&
            (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E34B8))
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
        if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) >= lbl_803E34B8)
        {
            ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A & 0xef;
            (*gExpgfxInterface)->freeSource2((u32)obj);
        }
    }
    if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        if ((((MagicDustState*)state)->flags27A & 2) != 0)
        {
            *(short*)obj = *(short*)obj + (u16)framesThisStep * 0x100;
            ((MagicDustState*)state)->ambientTimer -= (u16)framesThisStep;
            if (((MagicDustState*)state)->ambientTimer < 0)
            {
                Sfx_PlayFromObject(obj, SFXen_statue_wave);
                val = randomGetRange(0xf0, 300);
                ((MagicDustState*)state)->ambientTimer = (short)val;
            }
        }
        if (*(uint*)&((GameObject*)obj)->ownerObj != 0)
        {
            player = (int)((GameObject*)obj)->anim.modelState;
            if ((uint)player != 0)
            {
                ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
            (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
            goto LAB_80173f80;
        }
        ref = (int)((GameObject*)obj)->anim.modelState;
        if ((uint)ref != 0)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        *(undefined*)&((MagicDustState*)state)->unk25B = 1;
        fval = lbl_803E34BC;
        if ((((MagicDustState*)state)->flags27A & 3) == 0)
        {
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * fval;
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * fval;
            ((GameObject*)obj)->anim.velocityY = -(lbl_803E34C0 * timeDelta - ((GameObject*)obj)->anim.velocityY);
        }
        ((MagicDustState*)state)->burstTimer = ((MagicDustState*)state)->burstTimer - timeDelta;
        byteVal = ((MagicDustState*)state)->flags27A;
        if ((byteVal & 1) == 0)
        {
            if ((byteVal & 4) == 0)
            {
                if (((MagicDustState*)state)->burstTimer <= lbl_803E34C4)
                {
                    Obj_FreeObject(obj);
                }
                goto LAB_80173f80;
            }
            if (((MagicDustState*)state)->burstTimer <= lbl_803E34C4)
            {
                ((MagicDustState*)state)->flags27A = byteVal & 0xfb;
                ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 8;
                ((MagicDustState*)state)->burstTimer = lbl_803E34B4;
                (*gExpgfxInterface)->freeSource2((u32)obj);
                if (*(int*)&((GameObject*)obj)->anim.parent == 0)
                {
                    for (burstArg[0] = '\x1e'; burstArg[0] != '\0'; burstArg[0] = burstArg[0] + -1)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj,
                                                         ((MagicDustState*)state)->burstEffectId, NULL, 1, -1,
                                                         burstArg);
                    }
                }
                ((GameObject*)obj)->anim.alpha = 1;
                Sfx_PlayFromObject(obj, SFXen_waterblock_wave);
            }
            objMove(((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta, obj);
        }
        else
        {
            if (((MagicDustState*)state)->burstTimer <= lbl_803E34C4)
            {
                ((MagicDustState*)state)->flags27A = byteVal & 0xfe;
                ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 4;
                ((MagicDustState*)state)->burstTimer = lbl_803E34C8;
                ((GameObject*)obj)->anim.alpha = 0xff;
            }
            if (*(int*)&((GameObject*)obj)->anim.parent == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj,
                                                 ((MagicDustState*)state)->burstEffectId, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj,
                                                 ((MagicDustState*)state)->burstEffectId, NULL, 1, -1, NULL);
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
                if (lbl_803E34CC < mag)
                {
                    Sfx_PlayFromObject(obj, SFXwp_iceywindlp16);
                }
                if (((MagicDustState*)state)->unk6C < lbl_803E34D0)
                {
                    ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityX;
                    ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityZ;
                    fval = lbl_803E34D8;
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * lbl_803E34D8;
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * fval;
                }
                else
                {
                    ((GameObject*)obj)->anim.velocityY = -((GameObject*)obj)->anim.velocityY;
                    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803E34D4;
                }
                byteVal = *(char*)&((MagicDustState*)state)->bounceCount + 1;
                ((MagicDustState*)state)->bounceCount = byteVal;
                if (5 < byteVal)
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
        fval = ((GameObject*)obj)->anim.localPosY - *(float*)(player + 0x10);
        if (fval < lbl_803E34C4)
        {
            fval = -fval;
        }
        if (fval < lbl_803E34DC)
        {
            dist = getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18));
            fval = lbl_803E34E0 + ((MagicDustState*)state)->unk268;
            if ((dist < fval * fval) && (fn_8029622C(player) != 0))
            {
                val = GameBit_Get(0x90d);
                if (val == 0)
                {
                    *(undefined2*)&((MagicDustState*)state)->unk280 = 0xffff;
                    ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x280);
                    ObjHits_DisableObject(obj);
                    GameBit_Set(0x90d, 1);
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 0x20;
                }
                else
                {
                    ref = *(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x18);
                    (*gExpgfxInterface)->freeSource2((u32)obj);
                    itemPickupDoParticleFx(obj, lbl_803E34B0, ((MagicDustState*)state)->mode, 0x28);
                    ObjHits_DisableObject(obj);
                    Sfx_PlayFromObject(obj, (u16)((MagicDustState*)state)->sfxId);
                    Sfx_StopFromObject(obj, 0x56);
                    playerAddRemoveMagic(player, (int)*(s8*)(ref + 0xb));
                    ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A & 0xfa;
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

/*
 * --INFO--
 *
 * Function: magicdust_init
 * EN v1.0 Address: 0x80173B84
 * EN v1.0 Size: 1112b
 * EN v1.1 Address: 0x80173F98
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void magicdust_init(int obj, int placement)
{
    extern undefined4 ObjHits_DisableObject(); /* #57 */
    short mode;
    float chaseTime;
    uint randVal;
    int ref;
    int state;
    f32 ang;
    f32 spd;
    u16 texPickA[2];
    u16 texPickB[2];
    u8 pathArgs[4];
    undefined4 convHi0;
    uint convLo0;
    undefined4 convHi1;
    uint convLo1;
    undefined4 convHi2;
    uint convLo2;

    state = *(int*)&((GameObject*)obj)->extra;
    pathArgs[0] = 3;
    texPickA[0] = lbl_803E34A8;
    texPickB[0] = lbl_803E34AC;
    randVal = randomGetRange(0, 0xffff);
    spd = (f32)(int)
    randomGetRange(0x27, 0x2c) / lbl_803E34E4;
    ang = (lbl_803E34E8 * (f32)(int)
    randVal
    )
    /
    lbl_803E34EC;
    ((GameObject*)obj)->anim.velocityX = spd * mathSinf(ang);
    ((GameObject*)obj)->anim.velocityZ = spd * mathCosf(ang);
    ((GameObject*)obj)->anim.velocityY = (f32)(int)
    randomGetRange(0x28, 0x32) / lbl_803E34F0;
    mode = *(short*)(placement + 0x2e);
    if (mode == 1)
    {
        ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 1;
        ((GameObject*)obj)->anim.alpha = 1;
    }
    else if (mode == 2)
    {
        ((MagicDustState*)state)->flags27A = ((MagicDustState*)state)->flags27A | 1;
        ((GameObject*)obj)->anim.alpha = 1;
        if (*(uint*)&((GameObject*)obj)->anim.hitReactState != 0)
        {
            ObjHits_DisableObject(obj);
        }
        ref = (int)Obj_GetPlayerObject();
        chaseTime = lbl_803E34F4;
        ((GameObject*)obj)->anim.velocityX =
            (*(float*)(ref + 0xc) - ((GameObject*)obj)->anim.localPosX) / lbl_803E34F4;
        ((GameObject*)obj)->anim.velocityY = (*(float*)(ref + 0x10) - ((GameObject*)obj)->anim.localPosY) / chaseTime;
        ((GameObject*)obj)->anim.velocityZ = (*(float*)(ref + 0x14) - ((GameObject*)obj)->anim.localPosZ) / chaseTime;
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
    ((ObjAnimComponent*)obj)->bankIndex = *(u8*)(placement + 0x26);
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
        *(undefined*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickA + randVal);
        *(undefined2*)&((MagicDustState*)state)->ambientEffectId = 0x54f;
        *(undefined2*)&((MagicDustState*)state)->burstEffectId = 0x54b;
        *(undefined2*)&((MagicDustState*)state)->sfxId = 0x58;
        *(undefined2*)&((MagicDustState*)state)->unk276 = 0x5b0;
        *(undefined*)&((MagicDustState*)state)->mode = 4;
        break;
    case 0x2cd:
        randVal = randomGetRange(0, 1);
        *(undefined*)(*(int*)(ref + 0x34) + 8) = *(u8*)((int)texPickB + randVal);
        *(undefined2*)&((MagicDustState*)state)->ambientEffectId = 0x54e;
        *(undefined2*)&((MagicDustState*)state)->burstEffectId = 0x54a;
        *(undefined2*)&((MagicDustState*)state)->sfxId = 0x59;
        *(undefined2*)&((MagicDustState*)state)->unk276 = 0x5b1;
        *(undefined*)&((MagicDustState*)state)->mode = 1;
        break;
    case 0x2ce:
        *(undefined*)(*(int*)(ref + 0x34) + 8) = 3;
        *(undefined2*)&((MagicDustState*)state)->ambientEffectId = 0x54d;
        *(undefined2*)&((MagicDustState*)state)->burstEffectId = 0x549;
        *(undefined2*)&((MagicDustState*)state)->sfxId = 0x5a;
        *(undefined2*)&((MagicDustState*)state)->unk276 = 0x5b2;
        *(undefined*)&((MagicDustState*)state)->mode = 2;
        break;
    default:
        *(undefined*)(*(int*)(ref + 0x34) + 8) = 2;
        *(undefined2*)&((MagicDustState*)state)->ambientEffectId = 0x550;
        *(undefined2*)&((MagicDustState*)state)->burstEffectId = 0x54c;
        *(undefined2*)&((MagicDustState*)state)->sfxId = 0x5b;
        *(undefined2*)&((MagicDustState*)state)->unk276 = 0x5b3;
        *(undefined*)&((MagicDustState*)state)->mode = 6;
        break;
    }
    ((MagicDustState*)state)->unk268 = lbl_803E34F8;
    if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        (*gPathControlInterface)->init((void*)state, 0, 0x40007, 0);
        (*gPathControlInterface)->setup((void*)state, 1, lbl_80320CB8, (void*)(state + 0x268), pathArgs);
        (*gPathControlInterface)->attachObject((void*)obj, (void*)state);
    }
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
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


extern void fn_8002B758(void);

/*
 * --INFO--
 *
 * Function: effectbox_free
 * EN v1.0 Address: 0x80173F90
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void effectbox_free(void)
{
    fn_8002B758();
}


/* Trivial 4b 0-arg blr leaves. */
void effectbox_hitDetect(void)
{
}

void effectbox_release(void)
{
}

void effectbox_initialise(void)
{
}

extern void fn_8002B860(int obj);

void effectbox_init(int obj, int* def)
{
    s16 bit;
    u32 v;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        fn_8002B860(obj);
    }
    ((GameObject*)obj)->unkF4 = 1;
    bit = *(s16*)((char*)def + 0x20);
    if (bit > -1)
    {
        ((GameObject*)obj)->unkF8 = (int)bit;
    }
    else
    {
        ((GameObject*)obj)->unkF8 = -1;
    }
    v = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

/* 8b "li r3, N; blr" returners. */
int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3508;

void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3508);
}

void fn_80174588(int obj, PushableState* p2)
{
    extern int*objFindTexture(int, int, int);
    int data = *(int*)&((GameObject*)obj)->anim.placementData;

    switch (*(int*)(data + 0x14))
    {
    case 0x49B2C:
        p2->requiredHitId = 10;
        break;
    case 0x49B5D:
        p2->requiredHitId = 11;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        break;
    case 0x49B5E:
        p2->requiredHitId = 12;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        break;
    }

    if (GameBit_Get(*(s16*)(data + 0x18)) != 0)
    {
        int* tex;
        p2->flags = (u16)(p2->flags | 0x80);
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            *tex = 256;
        }
    }
}

extern void* getTrickyObject(void);
extern void fn_80295918(f32 amount, int obj, int p3);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int fn_80295A04(void* player, int p2);
extern int ObjGroup_FindNearestObject(int group, int obj, f32* dist);
extern int* objFindTexture(int obj, int a, int b);
extern void fn_80175428(int obj, int p2);
extern f32 lbl_803E350C;
extern f32 lbl_803E3510;
extern f32 lbl_803E3514;
extern f32 lbl_803E352C;
extern f64 lbl_803E3530;
extern f64 lbl_803E3538;
extern f32 lbl_803E3540;
extern f32 lbl_803E3544;
extern f32 lbl_803E3548;
extern f32 lbl_803E354C;
extern f32 lbl_803E3550;
extern f32 lbl_803E3554;
extern f32 lbl_803E3558;
extern f32 lbl_803E355C;
extern f32 lbl_803E3560;
extern f32 lbl_803E3564;
extern f32 lbl_803E3568;
extern f32 lbl_803E356C;
extern f32 lbl_803E3570;
extern f32 lbl_803E3528;

/*
 * --INFO--
 *
 * Function: effectbox_update
 * EN v1.0 Address: 0x80173FE4
 * EN v1.0 Size: 980b
 */
void effectbox_update(int obj)
{
    int def;
    int count;
    int single;
    int* list;
    int i;
    int other;
    f32 sinY;
    f32 cosY;
    f32 sinX;
    f32 cosX;
    f32 extX;
    f32 extYNeg;
    f32 extZ;
    f32 negExtX;
    f32 negExtZ;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 proj;
    int gb;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    gb = ((GameObject*)obj)->unkF8;
    if ((gb <= -1) || (((EffectboxPlacement*)def)->gameBitValue != GameBit_Get(gb)))
    {
        sinY = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        cosY = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        sinX = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        cosX = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        extX = (f32)((EffectboxPlacement*)def)->extentX;
        extYNeg = (f32) - (((EffectboxPlacement*)def)->extentY << 1);
        extZ = (f32)((EffectboxPlacement*)def)->extentZ;
        switch (((EffectboxPlacement*)def)->targetMode)
        {
        case 1:
            single = (int)Obj_GetPlayerObject();
            if (single == 0)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case 0:
            single = (int)getTrickyObject();
            if (single == 0)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case 2:
            list = (int*)ObjGroup_GetObjects(5, &count);
            if (list == NULL)
            {
                return;
            }
            break;
        }
        negExtX = -extX;
        negExtZ = -extZ;
        for (i = 0; i < count; i++)
        {
            other = *list;
            dx = *(f32*)(other + 0xc) - ((GameObject*)obj)->anim.localPosX;
            dy = *(f32*)(other + 0x10) - ((GameObject*)obj)->anim.localPosY;
            dz = *(f32*)(other + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            proj = dx * sinY + dz * cosY;
            if ((proj > negExtX) && (proj < extX))
            {
                proj = (-dx) * cosY + dz * sinY;
                proj = (-dy) * cosX + proj * sinX;
                if ((proj > negExtZ) && (proj < extZ))
                {
                    proj = dy * sinX + proj * cosX;
                    if ((proj >= lbl_803E3514) && (proj < extYNeg))
                    {
                        switch (((EffectboxPlacement*)def)->targetMode)
                        {
                        case 1:
                            break;
                        case 0:
                            fn_80295918((f32)((EffectboxPlacement*)def)->unk1D, other, 1);
                            break;
                        case 2:
                            (*(code*)(*(int*)(*(int*)(other + 0x68)) + 0x28))(other, ((EffectboxPlacement*)def)->unk1D);
                            break;
                        }
                    }
                }
            }
            list++;
        }
    }
}

/*
 * --INFO--
 *
 * Function: fn_80174438
 * EN v1.0 Address: 0x80174438
 * EN v1.0 Size: 336b
 */
int fn_80174438(int obj, PushableState* state)
{
    int def;
    void* player;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if (((state->flags & 0x80) != 0) || (fn_80295A04(player, 10) != 0))
    {
        Sfx_StopObjectChannel(obj, 8);
        return 0;
    }
    Sfx_PlayFromObject(obj, 0x66);
    state->flags |= 2;
    if ((state->flags & 4) == 0)
    {
        fn_80174BFC(obj, state);
    }
    if (((GameObject*)obj)->anim.localPosX <= lbl_803E352C + ((ObjPlacement*)def)->posX)
    {
        GameBit_Set(state->gameBit, 1);
        state->flags |= 0x80;
        ((GameObject*)obj)->anim.localPosX = (f32)(((ObjPlacement*)def)->posX - lbl_803E3530);
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = (f32)(lbl_803E3538 + ((ObjPlacement*)def)->posZ);
        Sfx_PlayFromObject(obj, 0x68);
    }
    if (GameBit_Get(0xa1a) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)def)->posX;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)def)->posZ;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_80174668
 * EN v1.0 Address: 0x80174668
 * EN v1.0 Size: 1048b
 */
int fn_80174668(int obj, PushableState* state)
{
    u8 flag;
    int* tex;
    void* effectResource;
    f32 dy;
    f32 dx;
    f32 cur;
    f32 bound;
    f32 p1;
    f32 p2;
    f32 dist[2];

    flag = 0;
    dist[0] = lbl_803E3540;
    fn_80175428(obj, 0);
    if (GameBit_Get(state->gameBit) != 0)
    {
        cur = ((GameObject*)obj)->anim.rootMotionScale;
        bound = lbl_803E3544;
        if (cur > bound)
        {
            ((GameObject*)obj)->anim.rootMotionScale = -(lbl_803E3548 * timeDelta - ((GameObject*)obj)->anim.
                rootMotionScale);
            if (((GameObject*)obj)->anim.rootMotionScale <= bound)
            {
                ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3528;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E354C;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        return 1;
    }
    if (state->nearestObj == NULL)
    {
        state->nearestObj = (void*)ObjGroup_FindNearestObject(0x11, obj, dist);
    }
    if (state->nearestObj == NULL)
    {
        return 0;
    }
    if (state->eyeOpenAmount < lbl_803E3550)
    {
        state->eyeOpenAmount = *(f32 *)&lbl_803E3550;
    }
    dy = *(f32*)((int)state->nearestObj + 0x14) - ((GameObject*)obj)->anim.localPosZ;
    if (dy < lbl_803E3528)
    {
        dy = dy * lbl_803E3554;
    }
    cur = state->unk_F0;
    if (cur < lbl_803E3558 + dy)
    {
        return 0;
    }
    dx = *(f32*)((int)state->nearestObj + 0xc) - ((GameObject*)obj)->anim.localPosX;
    if (dx < lbl_803E3528)
    {
        dx = dx * lbl_803E3554;
    }
    if (dx > lbl_803E355C)
    {
        return 0;
    }
    if ((cur >= lbl_803E3558 + dy) && (cur <= lbl_803E3560 + dy))
    {
        flag = 1;
        GameBit_Set(0x1c9, 1);
    }
    tex = (int*)objFindTexture(obj, 0, 0);
    state->blinkPhase = state->blinkStep * timeDelta + state->blinkPhase;
    if (state->blinkPhase >= state->blinkInterval)
    {
        state->blinkStep = state->blinkStep * lbl_803E3554;
    }
    else if (state->blinkPhase < lbl_803E3528)
    {
        state->blinkInterval = lbl_803E3564 * (f32)(int)
        randomGetRange(0x19, 0x4b);
        state->blinkStep = state->blinkInterval / (f32)(int)
        randomGetRange(0x28, 0x46);
        state->blinkPhase = lbl_803E3528;
    }
    if (tex != NULL)
    {
        state->eyeOpenAmount = state->eyeOpenAmount + state->eyeOpenSpeed;
        if (state->eyeOpenAmount >= lbl_803E3568)
        {
            GameBit_Set(state->gameBit, 1);
            if (flag)
            {
                GameBit_Set(0x1c9, 0);
            }
            effectResource = Resource_Acquire(0x5b, 1);
            (*(code*)(*(int*)(*(int*)effectResource + 4)))(obj, 0x14, 0, 2, -1, 0);
            (*(code*)(*(int*)(*(int*)effectResource + 4)))(obj, 0x14, 0, 2, -1, 0);
            Resource_Release(effectResource);
            Sfx_PlayFromObject(obj, 0x65);
        }
        else
        {
            state->eyePosX = state->eyePosX + state->eyeDriftSpeedX;
            if (state->eyePosX > lbl_803E356C)
            {
                state->eyePosX = lbl_803E356C;
            }
            else if (state->eyePosX < lbl_803E3528)
            {
                state->eyePosX = lbl_803E356C;
            }
            state->eyePosY = state->eyePosY + state->eyeDriftSpeedY;
            if (state->eyePosY > lbl_803E356C)
            {
                state->eyePosY = lbl_803E356C;
            }
            else if (state->eyePosY < lbl_803E3528)
            {
                state->eyePosY = lbl_803E356C;
            }
            p1 = state->eyePosX * (lbl_803E3570 + state->blinkPhase);
            p2 = state->eyePosY * (lbl_803E3570 + state->blinkPhase);
            *(u8*)((char*)tex + 0xc) = (u8)(int)
            state->eyeOpenAmount;
            *(u8*)((char*)tex + 0xd) = (u8)(int)
            p1;
            *(u8*)((char*)tex + 0xe) = (u8)(int)
            p2;
        }
    }
    return 0;
}
