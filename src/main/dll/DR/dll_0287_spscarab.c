/* === moved from main/dll/DR/DRpushcart.c [801E8EA4-801E8EE0) (TU re-split, docs/boundary_audit.md) === */
#include "main/effect_interfaces.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

typedef struct ShopitemState
{
    u8 pad0[0x88 - 0x0];
    s16 unk88;
    u8 pad8A[0xEC - 0x8A];
} ShopitemState;


typedef struct ShopitemPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} ShopitemPlacement;


/* shopitem_getExtraSize == 0xec (spline-following pushcart item). */
typedef struct ShopItemState
{
    u8 pad00[4];
    f32 controlX[4]; /* 0x04: B-spline control ring (address-passed, raw) */
    f32 controlY[4]; /* 0x14 */
    f32 controlZ[4]; /* 0x24 */
    u8 pad34[0xC];
    f32 splineT; /* 0x40 */
    f32 splineSpeed; /* 0x44 */
    u8 pad48[0x20];
    u8 segCounter; /* 0x68 */
    u8 pad69[0x1F];
    s16 msgParam; /* 0x88: ObjMsg payload (address-used, raw) */
    u8 pad8A[6];
    int vendorObj; /* 0x90: nearest group-9 shop manager */
    s16 helpTextId; /* 0x94 */
    u8 pad96;
    u8 flags97; /* 0x97: PushcartState97 overlay */
    u8 pad98[0xEC - 0x98];
} ShopItemState;

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);

/* shopkeeper_getExtraSize == 0x9d8. */
typedef struct ShopkeeperState
{
    u8 pad000[0x280];
    f32 animSpeed; /* 0x280 */
    u8 pad284[0x35C - 0x284];
    u8 dll2EBlock[0x96D - 0x35C]; /* 0x35c: dll_2E look-controller block (address-used) */
    u8 unk96D; /* 0x96d */
    u8 pad96E[0x980 - 0x96E];
    u8 eyeAnimBlock[0x9B0 - 0x980]; /* 0x980: characterDoEyeAnims block (address-used) */
    void* msgStack; /* 0x9b0: Stack_Free'd on free */
    int vendorObj; /* 0x9b4: nearest group-9 shop manager */
    f32 unk9B8; /* 0x9b8 */
    u8 pad9BC[8];
    f32 textTimer; /* 0x9c4: gameTextShow 0x433 countdown */
    s16 playerMoney; /* 0x9c8 */
    u8 pad9CA[2];
    s16 price; /* 0x9cc */
    s16 unk9CE; /* 0x9ce */
    s16 priceShown; /* 0x9d0 */
    u8 unk9D2; /* 0x9d2 */
    u8 pad9D3;
    u8 flags9D4; /* 0x9d4: 2 purchased-event, 4 facing, 0x10 leave, 0x20 tick */
    u8 amount; /* 0x9d5 */
    u8 opacity; /* 0x9d6: copied to obj alpha */
    u8 pad9D7;
} ShopkeeperState;

STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern void dll_2E_func06();
extern uint countLeadingZeros();

extern ScreenTransitionInterface** gScreenTransitionInterface;
extern undefined4* gBoneParticleEffectInterface;
extern f64 DOUBLE_803e6698;
extern f64 DOUBLE_803e66f0;
extern f32 lbl_803DC074;
extern f32 lbl_803E59D8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E6670;
extern f32 lbl_803E6674;
extern f32 lbl_803E6688;
extern f32 lbl_803E66B8;
extern f32 lbl_803E66BC;
extern f32 lbl_803E66C0;
extern f32 lbl_803E66C8;
extern f32 lbl_803E66CC;
extern f32 lbl_803E66D0;
extern f32 lbl_803E66D4;
extern f32 lbl_803E66D8;
extern f32 lbl_803E66DC;
extern f32 lbl_803E66E0;
extern f32 lbl_803E66E4;
extern f32 lbl_803E66E8;
extern f32 lbl_803E66F8;
extern void** gTitleMenuControlInterfaceCopy;

/*
 * --INFO--
 *
 * Function: FUN_801e76a0
 * EN v1.0 Address: 0x801E76A0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E7714
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e7be4
 * EN v1.0 Address: 0x801E7BE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E7C90
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e7be8
 * EN v1.0 Address: 0x801E7BE8
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801E823C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
void fn_801E7DC8(int p1, int p2, int count);

/*
 * --INFO--
 *
 * Function: FUN_801e7d3c
 * EN v1.0 Address: 0x801E7D3C
 * EN v1.0 Size: 688b
 * EN v1.1 Address: 0x801E83B8
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E7FEC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E85B4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Stack_Free();

#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E8014
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E85DC
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801e80b0
 * EN v1.0 Address: 0x801E80B0
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801E8680
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e8274
 * EN v1.0 Address: 0x801E8274
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E87C4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e8300
 * EN v1.0 Address: 0x801E8300
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801E89A0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e85b0
 * EN v1.0 Address: 0x801E85B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E8CE4
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e85b8
 * EN v1.0 Address: 0x801E85B8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801E8EA8
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
int fn_801E86F4(int obj, int p2, ObjSeqState* seq);


/* Trivial 4b 0-arg blr leaves. */
void shopkeeper_hitDetect(void);

void shopkeeper_release(void);

void shopitem_hitDetect(void);

void shopitem_release(void);

void shopitem_initialise(void);

void spscarab_render(void)
{
}

void spscarab_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int shopkeeper_getExtraSize(void);
int shopkeeper_getObjectTypeId(void);
int shopitem_getExtraSize(void);
int shopitem_getObjectTypeId(void);
int spscarab_getExtraSize(void) { return 0x14; }
int spscarab_getObjectTypeId(void) { return 0x0; }

extern void Sfx_RemoveLoopedObjectSound(int x, int y);
void spscarab_free(int x) { Sfx_RemoveLoopedObjectSound(x, 0x406); }

extern f32 lbl_803E5A30;
extern void fn_801E83B0(int obj, int, int, int, int);

void shopitem_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void shopitem_free(int obj);

extern void* lbl_803AD068[8];
extern void* lbl_803DDC58;
extern void DRlaserturret_startLinkedTarget(int);
extern void DRlaserturret_updateTracking(int);
extern void DRlaserturret_updateIdle(int);
extern void TREX_Lazerwall_updateTimedChallenge(int);
extern void TREX_Lazerwall_waitForStartBit(int);
extern void TREX_Lazerwall_popQueuedState(int);
extern void fn_801E66EC(int);
extern void fn_801E66E4(int);
extern void fn_801E66DC(int);

extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(u32 a, int b, u32 c);
extern void gxSetPeControl_ZCompLoc_(u32 a);
extern void GXSetAlphaCompare(int comp0, u8 ref0, int op, int comp1, u8 ref1);

void fn_801E832C(int obj);

void shopkeeper_initialise(void);

extern void hudFn_8011f38c(int);
extern f32 lbl_803E5A20;
extern f32 timeDelta;
extern f32 lbl_803E59DC;
extern void gameTextShow(int);
extern u32 ObjGroup_FindNearestObject(int kind, int obj, f32* out);
extern int playerGetMoney(void* player);
extern void characterDoEyeAnims(int obj, int p2);
extern void dll_2E_func03(int, int);
extern f32 shopKeeperRotateFn_801e7c4c(s16* obj, void* player, int mode);
extern int* gPlayerInterface;

typedef struct
{
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 bit20 : 1;
    u8 bit10 : 1;
    u8 bit08 : 1;
    u8 bit04 : 1;
    u8 bit02 : 1;
    u8 bit01 : 1;
} BitsAt9D4;

void shopkeeper_update(int obj);

extern f32 lbl_803E59F0;
extern f32 lbl_803E5A28;
extern void* allocModelStruct_800139e8(int, int);
extern void dll_2E_func05(int, int, int, int, int);
extern int fn_801E76A0(int obj, int p2, ObjSeqState* seq, s8 advance);
extern void ObjModel_SetPostRenderCallback(void*, void*);
extern void ObjGroup_AddObject(int, int);
extern void fn_801F4C28(int, int);
extern EffectInterface** gPartfxInterface;

void shopitem_init(int obj, int data);

void shopkeeper_init(int obj);

typedef struct
{
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} PushcartState97;


void fn_801E8660(int obj);

extern f32 lbl_803E5A60;
extern f32 lbl_803E5A64;
extern f32 lbl_803E5A68;
extern void ObjMsg_SendToObject(void* to, int msg, int obj, void* data);
extern void forceAButtonIcon(int icon);
extern void showHelpText(int textId);
extern void buttonDisable(int a, int b);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern void objRenderFn_80041018(int obj);
extern f32 Curve_EvalBSpline(int p, f32 t, int m);

void shopitem_update(int obj);

extern void DRlaserturret_startTimedChallenge(int);
extern void DRlaserturret_handlePromptChoice(int);
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern void warpToMap(int mapId, int flag);
extern int getCurUiDll(void);
extern int* getDLL16(void);
extern void playerAddMoney(void* player, int amount);
extern void* objFindTexture(int obj, int target, int p3);
extern int dll_2E_func07(int obj, u8* data, int p3, int p4, int p5);

int fn_801E76A0(int obj, int p2, ObjSeqState* seq, s8 advance);

extern f32 sqrtf(f32 x);
extern f32 lbl_803E5A24;

f32 shopKeeperRotateFn_801e7c4c(s16* obj, void* player, int mode);

extern f32 lbl_803E5A34;
extern f32 lbl_803E5A38;
extern f32 lbl_803E5A3C;
extern f32 lbl_803E5A40;
extern f32 lbl_803E5A44;
extern f32 lbl_803E5A48;
extern f32 lbl_803E5A4C;
extern f32 lbl_803E5A50;
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 radius, int c, int d, int e, f32 scale, int g, int h);
extern int ObjModel_GetRenderOp(int model, int idx);
extern void lightningRender(void);
extern int getHudHiddenFrameCount(void);
extern void mm_free_(int p);
extern int lightningCreate(f32* start, void* end, f32 a, f32 b, int c, int d, int e);

typedef struct ShopSparkleSpawn
{
    f32 x;
    f32 y;
    f32 z;
    int owner;
    u8 pad[0x28];
} ShopSparkleSpawn;

typedef struct PushcartStateE8
{
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} PushcartStateE8;

void fn_801E83B0(int obj, int p2, int p3, int p4, int p5);

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"

typedef struct SpscarabPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 unk19;
    u8 pad1A[0x20 - 0x1A];
} SpscarabPlacement;


typedef struct SpscarabState
{
    f32 unk0;
    f32 unk4;
    s32 unk8;
    s16 sfxId;
    s16 mode;
    s16 unk10;
    u8 pad12[0x18 - 0x12];
} SpscarabState;


extern f32 mathCosf(double x);
extern f32 mathSinf(double x); /* cos-like */
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern s16 getAngle(f32 dx, f32 dz);
extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void Vec3_ReflectAgainstNormal(int normal, int velocity, int out);
extern f32 getXZDistance(int* p1, int* p2);
extern void itemPickupDoParticleFx(int obj, f32 a, int b, int c);
extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5, int p6, f32 f2, int p7, int p8);

extern u16 lbl_803E5A70;
extern u8 lbl_803E5A72;
extern f32 lbl_803E5A74;
extern f32 lbl_803E5A78;
extern f32 lbl_803E5A7C;
extern f32 lbl_803E5A80;
extern f32 lbl_803E5A84;
extern f32 lbl_803E5A88;
extern f32 lbl_803E5A8C;
extern f32 lbl_803E5A90;
extern f32 lbl_803E5A94;
extern f64 lbl_803E5A98; /* int->float magic 0x4330000000000000 */


/*
 * --INFO--
 *
 * Function: spscarab_update
 * EN v1.0 Address: 0x801E8EE0
 * EN v1.0 Size: 588b
 */
void spscarab_update(int obj)
{
    extern int Obj_GetPlayerObject(void); /* #57 */
    int state;
    int placement;
    s16 angle;
    f32 distance;
    f32 phase; /* sp+0x10 */
    f32 outV[3]; /* sp+0x14 (output of Vec3_ReflectAgainstNormal) */
    f32 hit_buf[24]; /* sp+0x20 .. sp+0x80 (collision struct, objBboxFn_800640cc out) */

    state = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->anim.localPosY > ((SpscarabState*)state)->unk0)
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E5A74 * timeDelta;
    }

    objMove(obj,
            timeDelta * (((GameObject*)obj)->anim.velocityX * ((SpscarabState*)state)->unk4),
            ((GameObject*)obj)->anim.velocityY * timeDelta,
            timeDelta * (((GameObject*)obj)->anim.velocityZ * ((SpscarabState*)state)->unk4));

    distance = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
        ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);

    ObjAnim_SampleRootCurvePhase(distance, (ObjAnimComponent*)obj, &phase);
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, phase, timeDelta, 0);

    if (((GameObject*)obj)->anim.localPosY < ((SpscarabState*)state)->unk0)
    {
        ((GameObject*)obj)->anim.localPosY = ((SpscarabState*)state)->unk0;
        ((GameObject*)obj)->anim.velocityY = lbl_803E5A78;
    }

    if (objBboxFn_800640cc(obj + 0x80, obj + 0xc,
                           lbl_803E5A7C, 0, (int)&hit_buf[0] /* sp+0x20 */, obj,
                           8, -1, 0xff, 0xa) != 0)
    {
        Vec3_ReflectAgainstNormal((int)&hit_buf[7] /* sp+0x3c */, obj + 0x24, (int)outV);
        ((GameObject*)obj)->anim.velocityX = outV[0];
        ((GameObject*)obj)->anim.velocityZ = outV[2];
        angle = (s16)getAngle(-((GameObject*)obj)->anim.velocityX, -((GameObject*)obj)->anim.velocityZ);
        *(s16*)(obj) = angle;
    }

    if (getXZDistance((int*)(Obj_GetPlayerObject() + 0x18), (int*)&((GameObject*)obj)->anim.worldPosX)
        < lbl_803E5A80)
    {
        Sfx_PlayFromObject(obj, (u16)((SpscarabState*)state)->sfxId);
        itemPickupDoParticleFx(obj, lbl_803E5A84, ((SpscarabState*)state)->mode, 0x28);
        ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x8000;
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | 0x4000;

        {
            int r5val = (((SpscarabPlacement*)placement)->unk19 == 0) ? 1 : 0;
            int v3 = ((SpscarabState*)state)->unk8;
            int r4val = (((SpscarabPlacement*)placement)->unk19 == 0) ? 0 : 1;
            (*(void (**)(int, int, int))(*(int*)(*(int*)(v3 + 0x68)) + 0x50))(
                v3, r4val, r5val);
        }
    }

    if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
    {
        if (((SpscarabState*)state)->unk10 != 0)
        {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E5A84, (u8)((SpscarabState*)state)->unk10, 1, 0x14,
                                        lbl_803E5A88, 0, 0);
        }
    }
}

/*
 * --INFO--
 *
 * Function: spscarab_init
 * EN v1.0 Address: 0x801E912C
 * EN v1.0 Size: 500b
 */
void spscarab_init(int obj, int param_2)
{
    extern int Obj_GetActiveModel(int obj); /* #57 */
    extern int randomGetRange(int lo, int hi); /* #57 */
    ObjAnimComponent* objAnim;
    int p_b8;
    int model;
    struct
    {
        u16 a;
        u8 b;
    } pair;

    objAnim = (ObjAnimComponent*)obj;
    p_b8 = *(int*)&((GameObject*)obj)->extra;
    pair.a = lbl_803E5A70;
    pair.b = lbl_803E5A72;

    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x6000;
    *(s16*)(obj) = (s16)((s32)(s8) * (u8*)(param_2 + 0x18) << 8);

    ((GameObject*)obj)->anim.velocityX =
        -mathSinf(lbl_803E5A8C * (f32)(s32) * (s16*)(obj) /
            lbl_803E5A90);
    ((GameObject*)obj)->anim.velocityZ =
        -mathCosf(lbl_803E5A8C * (f32)(s32) * (s16*)(obj) /
            lbl_803E5A90);

    objAnim->bankIndex = (s8)(1 - *(u8*)(param_2 + 0x19));

    ((SpscarabState*)p_b8)->unk0 = (f32)(s32) * (s16*)(param_2 + 0x1a);
    ((SpscarabState*)p_b8)->unk4 = lbl_803E5A94 + (f32)randomGetRange(0, 0x64) / lbl_803E5A80;
    ((SpscarabState*)p_b8)->unk8 = *(int*)(param_2 + 0x14);
    *(int*)(param_2 + 0x14) = -1;

    Sfx_AddLoopedObjectSound(obj, 0x406);
    model = Obj_GetActiveModel(obj);

    switch ((s8) * (u8*)(param_2 + 0x19))
    {
    case 0:
        *(u8*)(*(int*)(model + 0x34) + 8) = *((u8*)&pair + randomGetRange(0, 2));
        ((SpscarabState*)p_b8)->sfxId = 0x41;
        ((SpscarabState*)p_b8)->mode = 4;
        ((SpscarabState*)p_b8)->unk10 = 2;
        break;
    case 1:
        ((SpscarabState*)p_b8)->sfxId = 0x42;
        ((SpscarabState*)p_b8)->mode = 1;
        ((SpscarabState*)p_b8)->unk10 = 0;
        break;
    }
}

/*
 * --INFO--
 *
 * Function: spscarab_release
 * EN v1.0 Address: 0x801E9320
 * EN v1.0 Size: 4b
 */
void spscarab_release(void)
{
}

/*
 * --INFO--
 *
 * Function: spscarab_initialise
 * EN v1.0 Address: 0x801E9324
 * EN v1.0 Size: 4b
 */
void spscarab_initialise(void)
{
}

ObjectDescriptor gSPScarabObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spscarab_initialise,
    (ObjectDescriptorCallback)spscarab_release,
    0,
    (ObjectDescriptorCallback)spscarab_init,
    (ObjectDescriptorCallback)spscarab_update,
    (ObjectDescriptorCallback)spscarab_hitDetect,
    (ObjectDescriptorCallback)spscarab_render,
    (ObjectDescriptorCallback)spscarab_free,
    (ObjectDescriptorCallback)spscarab_getObjectTypeId,
    spscarab_getExtraSize,
};

/*
 * --INFO--
 *
 * Function: spdrape_getExtraSize
 * EN v1.0 Address: 0x801E9328
 * EN v1.0 Size: 8b
 */

/*
 * --INFO--
 *
 * Function: spdrape_getObjectTypeId
 * EN v1.0 Address: 0x801E9330
 * EN v1.0 Size: 8b
 */

/*
 * --INFO--
 *
 * Function: spdrape_free
 * EN v1.0 Address: 0x801E9338
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spdrape_render
 * EN v1.0 Address: 0x801E933C
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spdrape_hitDetect
 * EN v1.0 Address: 0x801E9340
 * EN v1.0 Size: 4b
 */
