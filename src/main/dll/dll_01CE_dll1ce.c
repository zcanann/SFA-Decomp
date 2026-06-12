#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/explosion_state.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIM2flameburst.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct Dimwooddoor2Placement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} Dimwooddoor2Placement;


typedef struct ExplosionDebris
{
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    s32 unk14;
    f32 unk18;
    f32 unk1C;
    s32 unk20;
    s32 unk24;
    u16 unk28;
    u16 unk2A;
    u8 unk2C;
    u8 unk2D;
    u8 unk2E;
    u8 unk2F;
} ExplosionDebris;

typedef struct Dll1CEPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posYOffset;
    f32 posZ;
    u8 pad14[0x1A - 0x14];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 gameBitId;
} Dll1CEPlacement;


typedef struct DimmagicbridgeFlameSeqFnState
{
    u8 pad0[0x51 - 0x0];
    u8 unk51;
    u8 pad52[0x60 - 0x52];
    u16 unk60;
    u8 pad62[0x64 - 0x62];
    s16 unk64;
    u8 pad66[0x68 - 0x66];
} DimmagicbridgeFlameSeqFnState;


typedef struct FnExplosionReleaseV11UnusedState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    u8 padC[0x10 - 0xC];
} FnExplosionReleaseV11UnusedState;


/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */
typedef struct DimWoodDoor2State
{
    u8 burnState; /* 3 intact; 0 burned (gamebit rung) */
    u8 pad01[3];
    f32 animSpeed;
    f32 riseSpeed; /* added to obj Z, decays back to rest */
} DimWoodDoor2State;

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */
typedef struct Dll1CEState
{
    f32 openProgress; /* clamped lid coast */
    f32 openVelocity;
    u8 opened; /* 1 once triggered */
    u8 igniteCountdown; /* 1 at init; gamebit + spawn at 0 */
    u8 pad0A[2];
} Dll1CEState;

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

typedef struct ExplosionPartfxSource
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 flags;
    f32 rootMotionScale;
    f32 localPosX;
    f32 localPosY;
    f32 localPosZ;
    f32 worldPosX;
    f32 worldPosY;
    f32 worldPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* parent;
    u8 pad34[2];
    u8 alpha;
    u8 pad37;
} ExplosionPartfxSource;

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped. REFERENCE-ONLY for now:
 * every consumer keeps raw derefs - retyping the state local (or adding
 * (int) casts) flips saved-reg coloring in init/update/render/fn_801B3DE4
 * (recipe #36/#77); the layout is documented here for a future pass.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);


extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017924();
extern uint FUN_80017944();
extern int FUN_80017a54();
extern EffectInterface** gPartfxInterface;
extern undefined4 FUN_8002fc3c();
extern int FUN_80039520();
extern undefined4 FUN_80242114();
extern undefined8 FUN_80286834();
extern uint FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_802924b4();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f64 DOUBLE_803e56a8;
extern f32 lbl_803DC074;
extern f32 lbl_803DE7EC;
extern f32 lbl_803DE7F0;
extern f32 lbl_803E55C4;
extern f32 lbl_803E55C8;
extern f32 lbl_803E55D0;
extern f32 lbl_803E55D8;
extern f32 lbl_803E566C;
extern f32 lbl_803E5670;
extern f32 lbl_803E5674;
extern f32 lbl_803E5678;
extern f32 lbl_803E567C;
extern f32 lbl_803E569C;

/*
 * --INFO--
 *
 * Function: FUN_801b3de4
 * EN v1.0 Address: 0x801B3DE4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801B401C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3de4(undefined4 param_1, uint param_2)
{
    (*gObjectTriggerInterface)->runSequence((param_2 ^ 1) + 2, (void*)param_1, -1);
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801b40f0
 * EN v1.0 Address: 0x801B40F0
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x801B4398
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b40f0(undefined8 param_1, double param_2, double param_3, double param_4)
{
    byte bVar1;
    char cVar2;
    int iVar3;
    uint uVar4;
    u8 extraout_r4;
    int iVar5;
    int iVar6;
    int iVar7;
    int iVar8;
    double extraout_f1;
    double dVar9;
    double dVar10;

    uVar4 = FUN_8028683c();
    iVar5 = *(int*)(uVar4 + 0x4c);
    iVar6 = *(int*)(uVar4 + 0xb8);
    bVar1 = *(byte*)(iVar6 + 0xa58);
    *(byte*)(iVar6 + 0xa58) = bVar1 + 1;
    iVar7 = (uint)bVar1 * 0x30;
    *(float*)(iVar6 + iVar7) = (float)param_2;
    iVar8 = iVar6 + iVar7;
    *(float*)(iVar8 + 4) = (float)param_3;
    *(float*)(iVar8 + 8) = (float)param_4;
    *(float*)(iVar8 + 0x18) = lbl_803E55C4;
    *(undefined4*)(iVar8 + 0xc) = *(undefined4*)(iVar6 + 0x18);
    *(float*)(iVar8 + 0x1c) = (float)extraout_f1;
    *(u8*)(iVar8 + 0x2d) = extraout_r4;
    *(undefined4*)(iVar8 + 0x10) = 0;
    dVar9 = FUN_80293900(extraout_f1);
    *(int*)(iVar8 + 0x14) = (int)((double)lbl_803E55C8 * dVar9);
    iVar3 = *(int*)(iVar8 + 0x14);
    if (iVar3 < 0)
    {
        iVar3 = 0;
    }
    else if (0x3c < iVar3)
    {
        iVar3 = 0x3c;
    }
    *(int*)(iVar8 + 0x14) = iVar3;
    if ((*(char*)(iVar8 + 0x2d) != '\0') || (cVar2 = *(char*)(iVar5 + 0x19), cVar2 == '\0'))
        goto LAB_801b44d4;
    if (cVar2 == '\x02')
    {
        FUN_80006824(uVar4, 0x4bf);
        goto LAB_801b44d4;
    }
    if (cVar2 == '\x03')
    {
        FUN_80006824(uVar4, 0x4c2);
        goto LAB_801b44d4;
    }
    cVar2 = *(char*)(uVar4 + 0xac);
    if (cVar2 < ':')
    {
        if (cVar2 == ',')
        {
        LAB_801b44b4:
            FUN_800067e8(uVar4, 0x4b8, 2);
            goto LAB_801b44d4;
        }
    }
    else if (cVar2 < '?') goto LAB_801b44b4;
    FUN_80006824(uVar4, SFXthorntail_annoyed2);
LAB_801b44d4:
    uVar4 = randomGetRange(0, 0xffff);
    *(short*)(iVar6 + iVar7 + 0x28) = (short)uVar4;
    uVar4 = randomGetRange(200, 300);
    iVar3 = iVar6 + iVar7;
    *(short*)(iVar3 + 0x2a) = (short)uVar4;
    uVar4 = randomGetRange(0, 1);
    if (uVar4 != 0)
    {
        *(short*)(iVar3 + 0x2a) = -*(short*)(iVar3 + 0x2a);
    }
    uVar4 = randomGetRange(0, 3);
    *(char*)(iVar6 + iVar7 + 0x2c) = (char)uVar4;
    dVar10 = (double)*(float*)(iVar8 + 0x1c);
    dVar9 = (double)FUN_802924b4();
    *(float*)(iVar8 + 0xc) =
        -(float)((double)lbl_803DE7F0 *
            (double)(float)((double)(float)(dVar10 - (double)*(float*)(iVar8 + 0x18)) * dVar9)
            - dVar10);
    dVar9 = (double)FUN_802924b4();
    iVar6 = iVar6 + iVar7;
    *(char*)(iVar6 + 0x2e) =
        (char)(int)-(float)((double)lbl_803DE7EC * (double)(float)((double)lbl_803E55D0 * dVar9)
            - (double)lbl_803E55D0);
    *(int*)(iVar6 + 0x20) = (int)lbl_803E55D8;
    *(undefined4*)(iVar6 + 0x24) = *(undefined4*)(iVar6 + 0x20);
    *(u8*)(iVar6 + 0x2f) = 1;
    FUN_80286888();
    return;
}


/*
 * --INFO--
 *
 * Function: explosion_release
 * EN v1.0 Address: 0x801B5650
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B5DB8
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void textureFree(int tex);
extern int lbl_803AC960[4];

#pragma scheduling off
#pragma peephole off
void explosion_release(uint obj);

#pragma scheduling on
#pragma peephole on
void fn_explosion_release_v11_unused(uint param_1)
{
    short sVar1;
    float fVar2;
    bool bVar3;
    int iVar4;
    int iVar5;
    char* pcVar6;
    short* psVar7;

    psVar7 = *(short**)&((GameObject*)param_1)->anim.placementData;
    pcVar6 = ((GameObject*)param_1)->extra;
    FUN_8002fc3c((double)((FnExplosionReleaseV11UnusedState*)pcVar6)->unk4, (double)lbl_803DC074);
    ((GameObject*)param_1)->anim.localPosZ = ((GameObject*)param_1)->anim.localPosZ + ((FnExplosionReleaseV11UnusedState
        *)pcVar6)->unk8;
    fVar2 = lbl_803E566C;
    if (((FnExplosionReleaseV11UnusedState*)pcVar6)->unk8 != lbl_803E566C)
    {
        ((FnExplosionReleaseV11UnusedState*)pcVar6)->unk8 = ((FnExplosionReleaseV11UnusedState*)pcVar6)->unk8 *
            lbl_803E5670;
        if (((FnExplosionReleaseV11UnusedState*)pcVar6)->unk8 < fVar2)
        {
            fVar2 = ((FnExplosionReleaseV11UnusedState*)pcVar6)->unk8;
        }
        ((FnExplosionReleaseV11UnusedState*)pcVar6)->unk8 = fVar2;
    }
    if ((('\0' < *pcVar6) || (*psVar7 != 0x338)) || (((GameObject*)param_1)->anim.currentMoveProgress <= lbl_803E5674))
    {
        bVar3 = false;
        iVar5 = 0;
        iVar4 = (int)*(char*)(*(int*)(param_1 + 0x58) + 0x10f);
        if (0 < iVar4)
        {
            do
            {
                sVar1 = *(short*)(*(int*)(*(int*)(param_1 + 0x58) + iVar5 + 0x100) + 0x46);
                if ((sVar1 == 399) || (sVar1 == 0x1d6))
                {
                    bVar3 = true;
                    break;
                }
                iVar5 = iVar5 + 4;
                iVar4 = iVar4 + -1;
            }
            while (iVar4 != 0);
        }
        if (bVar3)
        {
            ((FnExplosionReleaseV11UnusedState*)pcVar6)->unk4 = lbl_803E5678;
            ((FnExplosionReleaseV11UnusedState*)pcVar6)->unk8 = lbl_803E567C;
            *pcVar6 = '\0';
            GameBit_Set((int)psVar7[0xf], 1);
            FUN_80006824(param_1, 0x3e1);
        }
    }
    else
    {
        iVar4 = (uint)((GameObject*)param_1)->anim.alpha + (uint)DAT_803dc070 * -0x10;
        if (iVar4 < 0)
        {
            iVar4 = 0;
        }
        (*(ObjHitsPriorityState**)&((GameObject*)param_1)->anim.hitReactState)->flags &= ~1;
        ((GameObject*)param_1)->anim.alpha = iVar4;
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801b5b8c
 * EN v1.0 Address: 0x801B5B8C
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801B62FC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5b8c(void)
{
    int iVar1;
    int* piVar2;
    undefined2* puVar3;
    short* psVar4;
    uint uVar5;
    int iVar6;
    int iVar7;
    uint uVar8;
    double dVar9;
    undefined8 uVar10;
    undefined8 local_58;
    undefined8 local_50;

    uVar10 = FUN_80286834();
    iVar1 = (int)((ulonglong)uVar10 >> 0x20);
    piVar2 = (int*)FUN_80017a54(iVar1);
    iVar6 = *piVar2;
    for (iVar7 = 0; uVar8 = (uint) * (ushort*)(iVar6 + 0xe4), iVar7 < (int)uVar8; iVar7 = iVar7 + 1)
    {
        puVar3 = (undefined2*)FUN_80017944((int)piVar2, iVar7);
        psVar4 = (short*)FUN_80017924(iVar6, iVar7);
        if (*psVar4 < 1)
        {
            dVar9 = (double)FUN_80293f90();
            local_50 = (double)CONCAT44(0x43300000, (int)*psVar4 ^ 0x80000000);
            *puVar3 = (short)(int)-(float)((double)lbl_803E569C * dVar9 -
                (double)(float)(local_50 - DOUBLE_803e56a8));
        }
        else
        {
            dVar9 = (double)FUN_80293f90();
            local_58 = (double)CONCAT44(0x43300000, (int)*psVar4 ^ 0x80000000);
            *puVar3 = (short)(int)((double)lbl_803E569C * dVar9 +
                (double)(float)(local_58 - DOUBLE_803e56a8));
        }
    }
    uVar5 = FUN_80017944((int)piVar2, 0);
    FUN_80242114(uVar5, uVar8 * 6);
    ((GameObject*)iVar1)->anim.alpha = *(u8*)((int)uVar10 + 0x51);
    FUN_80286880();
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b5d00
 * EN v1.0 Address: 0x801B5D00
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801B64D0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b5d00(int param_1, int param_2)
{
    int iVar1;
    uint uVar2;

    iVar1 = FUN_80039520(param_1, 0);
    *(short*)(iVar1 + 10) = *(short*)(iVar1 + 10) + 0x14;
    if (10000 < *(short*)(iVar1 + 10))
    {
        *(short*)(iVar1 + 10) = *(short*)(iVar1 + 10) + -10000;
    }
    *(short*)(iVar1 + 8) = *(short*)(iVar1 + 8) + 10;
    if (10000 < *(short*)(iVar1 + 8))
    {
        *(short*)(iVar1 + 8) = *(short*)(iVar1 + 8) + -10000;
    }
    iVar1 = FUN_80039520(param_1, 1);
    *(short*)(iVar1 + 10) = *(short*)(iVar1 + 10) + 0x1e;
    if (10000 < *(short*)(iVar1 + 10))
    {
        *(short*)(iVar1 + 10) = *(short*)(iVar1 + 10) + -10000;
    }
    uVar2 = (uint) * (ushort*)(param_2 + 0x60) + (uint)DAT_803dc070 * 0x100;
    if (0xffff < uVar2)
    {
        uVar2 = uVar2 - 0xffff;
    }
    *(short*)(param_2 + 0x60) = (short)uVar2;
    uVar2 = (uint) * (ushort*)(param_2 + 0x62) + (uint)DAT_803dc070 * 0x80;
    if (0xffff < uVar2)
    {
        uVar2 = uVar2 - 0xffff;
    }
    *(short*)(param_2 + 0x62) = (short)uVar2;
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void explosion_hitDetect(void);

void dimwooddoor2_free(void);

void dimwooddoor2_hitDetect(void);

void dimwooddoor2_release(void);

void dimwooddoor2_initialise(void);

void dll_1CE_hitDetect(void)
{
}

void dll_1CE_release(void)
{
}

void dll_1CE_initialise(void)
{
}

void dimmagicbridge_free(void);

void dimmagicbridge_hitDetect(void);

void dimmagicbridge_release(void);

void dimmagicbridge_initialise(void);

extern int Obj_GetActiveModel(int obj);
extern int ObjModel_GetCurrentVertexCoords(int model, int idx);
extern void fn_80065574(int a, int b, int c);

#pragma scheduling off
#pragma peephole off
void dimmagicbridge_init(u8* obj, u8* params);

/* 8b "li r3, N; blr" returners. */
int explosion_getExtraSize(void);
int dimwooddoor2_getExtraSize(void);
int dimwooddoor2_getObjectTypeId(void);
int dll_1CE_getExtraSize(void) { return 0xc; }
int dll_1CE_getObjectTypeId(void) { return 0x0; }
int dimmagicbridge_getExtraSize(void);
int dimmagicbridge_getObjectTypeId(void);
int dim_levelcontrol_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E49D0;
extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 v);
extern f32 lbl_803E49E8;
extern f32 lbl_803E4A18;

void dimwooddoor2_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49E8);
}

void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dim_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* conditional init/free pair. */
extern void* lbl_803DDB78;
#pragma scheduling on
#pragma peephole on
void dll_1CE_free(void)
{
    if (lbl_803DDB78 != NULL)
    {
        Resource_Release(lbl_803DDB78);
    }
    lbl_803DDB78 = NULL;
}

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */
extern f32 lbl_803E49D4;
extern f32 lbl_803E49F0;
extern void* Obj_GetPlayerObject(void);
extern void dimmagicbridge_scrollTextureChannels(int obj, u8* sub);
extern void dimmagicbridge_updateVertexWave(int obj, u8* sub);
extern int EmissionController_IsLingering(void* player);

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */
#pragma scheduling off
void dimmagicbridge_update(int obj);

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */
#pragma peephole off
void dimwooddoor2_init(u8* obj, u8* params);

void dll_1CE_init(u8* obj, u8* params)
{
    Dll1CEState* sub;
    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8
    )
    ;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    sub = ((GameObject*)obj)->extra;
    sub->igniteCountdown = 1;
    if (GameBit_Get(*(s16*)(params + 0x1e)) != 0)
    {
        sub->igniteCountdown = 0;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
    }
    sub->openVelocity = lbl_803E49F0;
}

/* explosion_free: model-light release if present. */
extern void ModelLightStruct_free(void*);
#pragma scheduling on
#pragma peephole on
void explosion_free(int obj);

/* explosion_getObjectTypeId: tile/index lookup capped by table count. */
#pragma scheduling off
int explosion_getObjectTypeId(int obj);

/* dim_levelcontrol_free: gameplay music + time-of-day reset. */
extern void Music_Trigger(s32 triggerId, s32 mode);

void dim_levelcontrol_free(int p1);

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern void* objFindTexture(int obj, int a, int b);
extern u8 framesThisStep;
#pragma dont_inline on
void dimmagicbridge_scrollTextureChannels(int arg1, u8* obj);
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */
#pragma peephole off
int dimmagicbridge_flameSeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);

extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E49D8;
extern f32 lbl_803E49DC;
extern f32 lbl_803E49E0;
extern f32 lbl_803E49E4;

/* EN v1.0 0x801B5804  size: 380b  dimwooddoor2_update: advance the door's
 * shake anim and decay its wobble; while idle near map-cue 0x338 bleed off
 * alpha, otherwise scan the nearby objects and, if a key object is present,
 * snap the door open (reset wobble, ring the gamebit, play the open sfx). */
void dimwooddoor2_update(int* obj);

extern int Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int a, int b);
extern void Obj_SetupObject(int* obj, int a, int b, int c, int d);
extern f32 lbl_803E49EC;
extern f32 lbl_803E49F4;
extern f32 lbl_803E49F8;
extern f32 lbl_803E49FC;

/* EN v1.0 0x801B5AA0  size: 496b  dll_1CE_update: hatch-door logic - coast
 * the lid open with clamped velocity while idle, and once a key object is
 * nearby, count down then ring the gamebit and (if the load isn't locked)
 * spawn the contents object seeded from the door's transform. */
void dll_1CE_update(int* obj)
{
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
    Dll1CEState* sub = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.alpha == 0) return;
    if ((s8)sub->igniteCountdown <= 0)
    {
        int* q2 = *(int**)&((GameObject*)obj)->anim.hitReactState;
        ((ObjHitsPriorityState*)q2)->flags = (s16)(((ObjHitsPriorityState*)q2)->flags & ~1);
        if (sub->opened == 1)
        {
            sub->openProgress = sub->openVelocity * timeDelta + sub->openProgress;
            if (sub->openProgress > lbl_803E49EC)
            {
                sub->openProgress = lbl_803E49EC;
                sub->openVelocity = lbl_803E49F0;
            }
            else if (sub->openProgress < lbl_803E49F4)
            {
                sub->openProgress = lbl_803E49F4;
                sub->openVelocity = lbl_803E49F8;
            }
        }
    }
    if (((GameObject*)obj)->anim.seqId == 0x334) return;
    {
        int found = 0;
        int i;
        int* list = *(int**)((char*)obj + 0x58);
        int n = (s8) * (s8*)((char*)list + 0x10f);
        for (i = 0; i < n; i++)
        {
            int* o = *(int**)((char*)list + 0x100 + i * 4);
            if (*(s16*)((char*)o + 0x46) == 0x18f || *(s16*)((char*)o + 0x46) == 0x1d6)
            {
                found = 1;
                break;
            }
        }
        if (!found) return;
    }
    sub->igniteCountdown -= 1;
    if ((s8)sub->igniteCountdown > 0) return;
    GameBit_Set(((Dll1CEPlacement*)q)->gameBitId, 1);
    sub->opened = 1;
    if ((s16)((Dll1CEPlacement*)q)->unk1A != (int)GameBit_Get(0x46d)) return;
    if (Obj_IsLoadingLocked() == 0) return;
    {
        int* no = Obj_AllocObjectSetup(0x30, 0x246);
        *(f32*)((char*)no + 8) = ((Dll1CEPlacement*)q)->posX;
        *(f32*)((char*)no + 0xc) = lbl_803E49FC + ((Dll1CEPlacement*)q)->posYOffset;
        *(f32*)&((ObjDef*)no)->jointData = ((Dll1CEPlacement*)q)->posZ;
        *(u8*)((char*)no + 4) = ((Dll1CEPlacement*)q)->unk4;
        *(u8*)((char*)no + 5) = ((Dll1CEPlacement*)q)->unk5;
        *(u8*)((char*)no + 6) = ((Dll1CEPlacement*)q)->unk6;
        *(u8*)((char*)no + 7) = ((Dll1CEPlacement*)q)->unk7;
        *(s16*)((char*)no + 0x1c) = 0x17f;
        *(s16*)((char*)no + 0x24) = -1;
        *(s16*)((char*)no + 0x2c) = -1;
        *(u8*)((char*)no + 0x1a) = 5;
        *(u8*)((char*)no + 0x1b) = (u8)((s16) * (s16*)obj >> 8);
        Obj_SetupObject(no, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    }
}

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} FbWGPipe;

volatile FbWGPipe GXWGFifo : (0xCC008000);

typedef struct
{
    int v[4];
} FbTexTbl;

extern f32 lbl_803E492C;
extern f32 lbl_803E4930;
extern f32 lbl_803E4934;
extern f32 lbl_803E4938;
extern f32 lbl_803E493C;
extern f32 lbl_803E4940;
extern f32 lbl_803E4950;
extern f32 lbl_803E4954;
extern f32 lbl_803E4958;
extern f32 lbl_803E495C;
extern f32 lbl_803E4960;
extern f64 lbl_803E4968;
extern f32 lbl_803E4970;
extern f32 lbl_803E4974;
extern f64 lbl_803E4978;
extern f64 lbl_803E4980;
extern f32 lbl_803E4988;
extern f32 lbl_803E4998;
extern f32 lbl_803E499C;
extern f32 lbl_803E49A0;
extern f32 lbl_803E49A4;
extern f32 lbl_803E49A8;
extern f32 lbl_803E49AC;
extern f32 lbl_803E49B0;
extern f32 lbl_803E49B4;
extern f32 lbl_803E49B8;
extern f32 lbl_803E49BC;
extern f32 lbl_803E49C0;
extern f32 lbl_803E49C4;
extern f32 lbl_803E49C8;
extern f32 lbl_803E49CC;
extern int lbl_803E4928;
extern int lbl_803E8468;
extern u8 lbl_803DDB58;
extern f32 lbl_803DDB5C;
extern f32 lbl_803DDB60;
extern f32 lbl_803DDB64;
extern f32 lbl_803DDB68;
extern f32 lbl_803DDB6C;
extern f32 lbl_803DDB70;
extern f32 lbl_803DCDD8;
extern f32 lbl_803DCDDC;
extern f32 lbl_80325528[];
extern FbTexTbl lbl_802C2328;
extern f32 lbl_803E4A00;
extern f32 lbl_803E4A04;
extern f32 lbl_803E4A08;
extern f32 lbl_803E4A0C;
extern int ObjModel_GetBaseVertexCoords(int mdl, int idx);

extern f32 expf(f32 x);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern void Sfx_PlayFromObjectLimited(int obj, int id, int n);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCurrentMtx(int id);
extern void GXLoadPosMtxImm(f32* m, int id);
extern void GXBegin(int prim, int fmt, int n);
extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXMultVecSR(f32 * m, f32 * in, f32 * out);
extern f32* Camera_GetViewMatrix(void);
extern f32* Camera_GetInverseViewRotationMatrix(void);
extern int fn_8000FA70(void);
extern int fn_8000FA90(void);
extern void fn_80073AAC(void* tex, u32* a, u32* b, int k);
extern void Obj_BuildWorldTransformMatrix(int obj, f32* m, int p3);
extern void renderResetFn_8003fc60(void);
extern int textureLoadAsset(int id);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int hitDetectFn_800658a4(int obj, int out, int p3, f32 x, f32 y, f32 z);
extern int objCreateLight(int a, int b);
extern void modelLightStruct_setLightKind(int h, int v);
extern void modelLightStruct_setPosition(int h, f32 x, f32 y, f32 z);
extern void modelLightStruct_setAffectsAabbLightSelection(int h, int v);
extern void modelLightStruct_setEnabled(int h, int n, f32 v);
extern void modelLightStruct_setDistanceAttenuation(int h, f32 a, f32 b);
extern void modelLightStruct_setDiffuseColor(int h, int r, int g, int b, int a);
extern void Obj_FreeObject(int obj);
extern void DCStoreRange(void* p, int n);
extern void* memcpy(void* dst, const void* src, unsigned long n);

void fn_801B3DE4(int obj, int b, f32 spd, f32 x, f32 y, f32 z);
void fn_801B40B8(u8 mode, u8* out, f32 a, f32 b);

void fn_801B3DE4(int obj, int b, f32 spd, f32 x, f32 y, f32 z);

void fn_801B40B8(u8 mode, u8* out, f32 a, f32 b);

void explosion_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void explosion_update(int obj);

void explosion_init(int obj, int p2);

void explosion_initialise(void);

void dimmagicbridge_updateVertexWave(int obj, u8* sub);
