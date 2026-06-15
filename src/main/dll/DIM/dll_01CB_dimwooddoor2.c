#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dimwooddoor2placement_struct.h"
#include "main/dll/fnexplosionreleasev11unusedstate_struct.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/explosion_state.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objseq.h"

/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

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

extern f32 lbl_803E49D0;
extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 v);
extern f32 lbl_803E49D4;
extern u8 framesThisStep;
extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E49D8;
extern f32 lbl_803E49DC;
extern f32 lbl_803E49E0;
extern f32 lbl_803E49E4;

void FUN_801b3de4(undefined4 param_1, uint param_2)
{
    (*gObjectTriggerInterface)->runSequence((param_2 ^ 1) + 2, (void*)param_1, -1);
    return;
}

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

void explosion_release(uint obj);

void fn_explosion_release_v11_unused(uint obj)
{
    short moveId;
    float minSpeed;
    bool sequenceDone;
    int count;
    int idx;
    char* state;
    short* placement;
    ObjHitsPriorityState* hitState;

    placement = *(short**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    FUN_8002fc3c((double)((FnExplosionReleaseV11UnusedState*)state)->unk4, (double)lbl_803DC074);
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + ((FnExplosionReleaseV11UnusedState
        *)state)->unk8;
    minSpeed = lbl_803E566C;
    if (((FnExplosionReleaseV11UnusedState*)state)->unk8 != lbl_803E566C)
    {
        ((FnExplosionReleaseV11UnusedState*)state)->unk8 = ((FnExplosionReleaseV11UnusedState*)state)->unk8 *
            lbl_803E5670;
        if (((FnExplosionReleaseV11UnusedState*)state)->unk8 < minSpeed)
        {
            minSpeed = ((FnExplosionReleaseV11UnusedState*)state)->unk8;
        }
        ((FnExplosionReleaseV11UnusedState*)state)->unk8 = minSpeed;
    }
    if ((('\0' < *state) || (*placement != 0x338)) || (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E5674))
    {
        sequenceDone = false;
        idx = 0;
        count = (int)*(char*)(*(int*)(obj + 0x58) + 0x10f);
        if (0 < count)
        {
            do
            {
                moveId = *(short*)(*(int*)(*(int*)(obj + 0x58) + idx + 0x100) + 0x46);
                if ((moveId == 399) || (moveId == 0x1d6))
                {
                    sequenceDone = true;
                    break;
                }
                idx = idx + 4;
                count = count + -1;
            }
            while (count != 0);
        }
        if (sequenceDone)
        {
            ((FnExplosionReleaseV11UnusedState*)state)->unk4 = lbl_803E5678;
            ((FnExplosionReleaseV11UnusedState*)state)->unk8 = lbl_803E567C;
            *state = '\0';
            GameBit_Set((int)placement[0xf], 1);
            FUN_80006824(obj, 0x3e1);
        }
    }
    else
    {
        count = (uint)((GameObject*)obj)->anim.alpha + (uint)DAT_803dc070 * -0x10;
        if (count < 0)
        {
            count = 0;
        }
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = count;
    }
    return;
}

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

void explosion_hitDetect(void);

void dimwooddoor2_free(void)
{
}

void dimwooddoor2_hitDetect(void)
{
}

void dimwooddoor2_release(void)
{
}

void dimwooddoor2_initialise(void)
{
}

void dll_1CE_hitDetect(void);

int dimwooddoor2_getExtraSize(void) { return 0xc; }
int dimwooddoor2_getObjectTypeId(void) { return 0x0; }
int dll_1CE_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void dimwooddoor2_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49D0);
}

void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */
void dimwooddoor2_init(u8* obj, u8* params)
{
    DimWoodDoor2State* sub;
    ObjHitsPriorityState* hitState;
    f32 fz;
    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8
    )
    ;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    sub = ((GameObject*)obj)->extra;
    sub->burnState = 3;
    fz = lbl_803E49D4;
    sub->animSpeed = fz;
    sub->riseSpeed = fz;
    if (GameBit_Get(*(s16*)(params + 0x1e)) != 0)
    {
        sub->burnState = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
    }
}

void dll_1CE_init(u8* obj, u8* params);

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
#pragma dont_inline on
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

/* EN v1.0 0x801B5804  size: 380b  dimwooddoor2_update: advance the door's
 * shake anim and decay its wobble; while idle near map-cue 0x338 bleed off
 * alpha, otherwise scan the nearby objects and, if a key object is present,
 * snap the door open (reset wobble, ring the gamebit, play the open sfx). */
void dimwooddoor2_update(int* obj)
{
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
    DimWoodDoor2State* sub = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    ObjAnim_AdvanceCurrentMove(sub->animSpeed, timeDelta, (int)obj, 0);
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + sub->riseSpeed;
    {
        f32 rs = sub->riseSpeed;
        f32 ceil = lbl_803E49D4;
        if (rs != ceil)
        {
            sub->riseSpeed = rs * lbl_803E49D8;
            sub->riseSpeed = (sub->riseSpeed < ceil) ? sub->riseSpeed : ceil;
        }
    }
    if ((s8)sub->burnState <= 0 && *(s16*)q == 0x338 && ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E49DC)
    {
        int v = ((GameObject*)obj)->anim.alpha - framesThisStep * 16;
        if (v < 0) v = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = (u8)v;
    }
    else
    {
        int found;
        int i;
        int objAddr = (int)obj;
        found = 0;
        for (i = 0; i < (int)*(s8*)(*(int*)(objAddr + 0x58) + 0x10f); i++)
        {
            int o = *(int*)(*(int*)(objAddr + 0x58) + i * 4 + 0x100);
            if (*(s16*)(o + 0x46) == 0x18f || *(s16*)(o + 0x46) == 0x1d6)
            {
                found = 1;
                break;
            }
        }
        if (found)
        {
            sub->animSpeed = lbl_803E49E0;
            sub->riseSpeed = lbl_803E49E4;
            sub->burnState = 0;
            GameBit_Set(((Dimwooddoor2Placement*)q)->unk1E, 1);
            Sfx_PlayFromObject((int)obj, 0x3e1);
        }
    }
}

volatile FbWGPipe GXWGFifo : (0xCC008000);
