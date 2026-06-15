#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/explosiondebris_struct.h"
#include "main/dll/fbtextbl_struct.h"
#include "main/dll/fnexplosionreleasev11unusedstate_struct.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/explosion_state.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIM2flameburst.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/resource.h"

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

extern void textureFree(int tex);
extern int lbl_803AC960[4];
extern int Obj_GetActiveModel(int obj);
extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 v);
extern void dimmagicbridge_updateVertexWave(int obj, u8* sub);
extern void ModelLightStruct_free(void*);
extern void Music_Trigger(s32 triggerId, s32 mode);
extern u8 framesThisStep;
extern void Sfx_PlayFromObject(int obj, int sfxId);
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
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_80325528[];
extern FbTexTbl lbl_802C2328;
extern f32 expf(f32 x);
extern f32 sqrtf(f32 x);
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
extern void* memcpy(void* dst, const void* src, unsigned long n);

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

#pragma scheduling off
#pragma peephole off
void explosion_release(uint obj)
{
    int i;

    for (i = 0; i < 4; i++)
    {
        if (((int**)lbl_803AC960)[i] != NULL)
        {
            textureFree((int)((int**)lbl_803AC960)[i]);
            ((int**)lbl_803AC960)[i] = NULL;
        }
    }
}

#pragma scheduling on
#pragma peephole on
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

void explosion_hitDetect(void)
{
}

void dimwooddoor2_free(void);

int explosion_getExtraSize(void) { return 0xa60; }
int dimwooddoor2_getExtraSize(void);

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

void explosion_free(int obj)
{
    void* p = *(void**)(*(int*)&((GameObject*)obj)->extra + 0xa40);
    if (p != NULL)
    {
        ModelLightStruct_free(p);
    }
}

#pragma scheduling off
int explosion_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int idx = (int)*(short*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1c) & 3;
    if (idx >= objAnim->modelInstance->modelCount)
    {
        idx = 0;
    }
    return (idx << 11) | 0x400;
}

void dim_levelcontrol_free(int p1);

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
#pragma dont_inline on
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

volatile FbWGPipe GXWGFifo : (0xCC008000);

void fn_801B3DE4(int obj, u8 b, f32 spd, f32 x, f32 y, f32 z);
void fn_801B40B8(f32 a, f32 b, u8 mode, u8* out);
typedef void (*Fn801B40B8IntFirst)(u8 mode, u8* out, f32 a, f32 b);
typedef void (*Fn801B3DE4SpdFirst)(int obj, f32 spd, int b, f32 x, f32 y, f32 z);
typedef int (*HitDetectFloatsFirst)(int obj, f32 x, f32 y, f32 z, int out, int p3);

#pragma peephole off
#pragma opt_propagation off
void fn_801B3DE4(int obj, u8 b, f32 spd, f32 x, f32 y, f32 z)
{
    int p4c = *(int*)&((GameObject*)obj)->anim.placementData;
    int state = *(int*)&((GameObject*)obj)->extra;
    int idx;
    int off;
    int e;
    int e14;
    idx = ((ExplosionState*)state)->flameCount++;
    off = idx * 0x30;
    *(f32*)((char*)state + off) = x;
    e = state + off;
    *(f32*)((char*)e + 0x4) = y;
    *(f32*)((char*)e + 0x8) = z;
    *(f32*)((char*)e + 0x18) = lbl_803E492C;
    *(f32*)((char*)e + 0xc) = *(f32*)((char*)state + 0x18);
    *(f32*)((char*)e + 0x1c) = spd;
    *(u8*)((char*)e + 0x2d) = b;
    *(int*)((char*)e + 0x10) = 0;
    e14 = state + off;
    *(int*)((char*)e14 + 0x14) = (int)(lbl_803E4930 * sqrtf(spd));
    {
        int v = *(int*)((char*)e14 + 0x14);
        if (v < 0)
        {
            v = 0;
        }
        else if (v > 0x3c)
        {
            v = 0x3c;
        }
        *(int*)((char*)e14 + 0x14) = v;
    }
    if (*(u8*)((char*)e + 0x2d) < 1)
    {
        s8 c = *(s8*)((char*)p4c + 0x19);
        if (c != 0)
        {
            if (c == 2)
            {
                Sfx_PlayFromObject(obj, 0x4bf);
            }
            else if (c == 3)
            {
                Sfx_PlayFromObject(obj, 0x4c2);
            }
            else
            {
                s8 m = ((GameObject*)obj)->anim.mapEventSlot;
                if (m < 0x3a)
                {
                    if (m == 0x2c)
                    {
                        goto playLimited;
                    }
                }
                else if (m < 0x3f)
                {
                playLimited:
                    Sfx_PlayFromObjectLimited(obj, 0x4b8, 2);
                    goto done;
                }
                Sfx_PlayFromObject(obj, 0x203);
            done:;
            }
        }
    }
    *(s16*)((char*)state + idx * 0x30 + 0x28) = randomGetRange(0, 0xffff);
    *(s16*)((char*)state + idx * 0x30 + 0x2a) = randomGetRange(0xc8, 0x12c);
    if ((int)randomGetRange(0, 1) != 0)
    {
        *(s16*)((char*)state + idx * 0x30 + 0x2a) = -*(s16*)((char*)state + idx * 0x30 + 0x2a);
    }
    *(u8*)((char*)state + idx * 0x30 + 0x2c) = randomGetRange(0, 3);
    {
        f32 sp = *(f32*)((char*)e + 0x1c);
        f32 ev = expf(
            (lbl_803E4934 * ((f32)(int) * (int*)((char*)e14 + 0x14) - (f32)(int) * (int*)((char*)e + 0x10))) / (f32)(int)
            * (int*)((char*)e14 + 0x14));
        f32 d = sp - *(f32*)((char*)e + 0x18);
        f32 t = d * ev;
        *(f32*)((char*)e + 0xc) = sp - lbl_803DDB70 * t;
        ev = expf((lbl_803E493C * (f32)(int) * (int*)((char*)e + 0x10)) / (f32)(int) * (int*)((char*)e14 + 0x14));
        t = lbl_803E4938 * ev;
        *(s8*)((char*)state + idx * 0x30 + 0x2e) = lbl_803E4938 - lbl_803DDB6C * t;
        *(int*)((char*)state + idx * 0x30 + 0x20) = (int)lbl_803E4940;
        *(int*)((char*)state + idx * 0x30 + 0x24) = *(int*)((char*)state + idx * 0x30 + 0x20);
        *(u8*)((char*)state + idx * 0x30 + 0x2f) = 1;
    }
}
#pragma opt_propagation reset

#pragma dont_inline on
void fn_801B40B8(f32 a, f32 b, u8 mode, u8* out)
{
    s16 v1;
    s16 v2;
    s16 v3;
    s16 c1;
    s16 c2;
    s16 c3;
    c1 = 0xff - (u8)(int)(lbl_803DDB64 * (lbl_803E4938 * expf((lbl_803E4950 * a) / b)));
    c2 = 0xff - (u8)(int)(lbl_803DDB60 * (lbl_803E4938 * expf((lbl_803E4954 * a) / b)));
    c3 = 0xff - (u8)(int)(lbl_803DDB5C * (lbl_803E4938 * expf(a / b)));
    v1 = (c1 < 1) ? 1 : ((c1 > 0xff) ? 0xff : c1);
    v2 = (c2 < 1) ? 1 : ((c2 > 0xff) ? 0xff : c2);
    v3 = (c3 < 1) ? 1 : ((c3 > 0xff) ? 0xff : c3);
    switch (mode)
    {
    case 0:
        out[0] = v1;
        out[1] = v2;
        out[2] = v3;
        break;
    case 1:
        out[0] = v1;
        out[1] = v3;
        out[2] = v3;
        break;
    case 2:
        out[0] = v3;
        out[1] = v1;
        out[2] = v3;
        break;
    case 3:
        out[0] = v3;
        out[1] = v3;
        out[2] = v1;
        break;
    }
}

#pragma dont_inline reset
void explosion_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u32 colA;
    u32 colB;
    u32 colA2;
    u32 colB2;
    f32 mE[12];
    f32 m4[12];
    f32 m3[12];
    f32 m2[12];
    f32 m1[12];
    int state;
    int model;
    int i;
    int p;
    colA = lbl_803E4928;
    colB = lbl_803E8468;
    state = *(int*)&((GameObject*)obj)->extra;
    model = Obj_GetActiveModel((int)obj);
    p = state;
    if (visible != 0)
    {
        GXClearVtxDesc();
        GXSetVtxDesc(9, 1);
        GXSetVtxDesc(0xd, 1);
        GXSetCurrentMtx(0);
        for (i = 0, p = state; i < ((ExplosionState*)state)->flameCount; i++)
        {
            if (*(u8*)&((ExplosionDebris*)p)->unk2F != 0)
            {
                void** tex;
                int k;
                u8 cv;
                Obj_BuildWorldTransformMatrix(obj, mE, 0);
                PSMTXRotRad(
                    m1, 0x7a, (f32)((lbl_803E4978 * (f64)(int) * (s16*)&((ExplosionDebris*)p)->unk28) / lbl_803E4980));
                PSMTXRotRad(
                    m3, 0x78, (f32)((lbl_803E4978 * ((f64)(u32)(fn_8000FA70() & 0xffff) - 0.0)) / lbl_803E4980));
                PSMTXConcat(m3, m1, m3);
                PSMTXRotRad(
                    m2, 0x79, (f32)((lbl_803E4978 * (f64)(int)(0x10000 - (fn_8000FA90() & 0xffff))) / lbl_803E4980));
                PSMTXConcat(m2, m3, m2);
                PSMTXScale(m4, ((ExplosionDebris*)p)->unkC, ((ExplosionDebris*)p)->unkC, ((ExplosionDebris*)p)->unkC);
                PSMTXConcat(m4, m2, m4);
                PSMTXTrans(mE, ((ExplosionDebris*)p)->unk0 - playerMapOffsetX, ((ExplosionDebris*)p)->unk4,
                           ((ExplosionDebris*)p)->unk8 - playerMapOffsetZ);
                PSMTXConcat(mE, m4, mE);
                PSMTXConcat(Camera_GetViewMatrix(), mE, mE);
                GXLoadPosMtxImm(mE, 0);
                ((u8*)&colA)[3] = ((ExplosionDebris*)p)->unk2E;
                cv = lbl_803DDB68 * (lbl_803E4938 * expf(
                    (lbl_803E4958 * ((f32)(int)((ExplosionDebris*)p)->unk14 - (f32)(int)((ExplosionDebris*)p)->unk10)) /
                    (f32)(int)((ExplosionDebris*)p)->unk14));
                ((u8*)&colB)[0] = cv;
                ((u8*)&colB)[1] = cv;
                ((u8*)&colB)[2] = cv;
                ((u8*)&colB)[3] = cv;
                fn_801B40B8((f32)(int)((ExplosionDebris*)p)->unk10,
                            (f32)(int)((ExplosionDebris*)p)->unk14,
                            ((ExplosionState*)state)->modelKind, (u8*)&colA);
                tex = (void**)((int*)lbl_803AC960)[((ExplosionState*)state)->modelKind];
                for (k = 0; k < ((ExplosionDebris*)p)->unk2C; k++)
                {
                    tex = (void**)*tex;
                }
                colB2 = colB;
                colA2 = colA;
                fn_80073AAC(tex, &colA2, &colB2, k);
                GXBegin(0x80, 2, 4);
                {
                    f32 fc = lbl_803E492C;
                    f32 fb = lbl_803E4960;
                    f32 fa = lbl_803E4988;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                }
            }
            p += 0x30;
        }
        if (((ExplosionState*)state)->frameCounter < ((ExplosionState*)state)->lifeFrames && *(u8*)&((ExplosionState*)
            state)->rayMode != 0)
        {
            for (i = 0, p = state; i < ((ExplosionState*)state)->rayMode; i++, p += 4)
            {
                ((GameObject*)obj)->anim.rotY = (s16)*(u16*)&((ExplosionState*)p)->rayYawA;
                ((GameObject*)obj)->anim.rotX = (s16)*(u16*)&((ExplosionState*)p)->rayPitchA;
                objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (f32)visible);
                if (i < ((ExplosionState*)state)->rayMode - 1)
                {
                    *(u16*)((char*)model + 0x18) &= ~8;
                }
            }
        }
    }
    renderResetFn_8003fc60();
}

#pragma opt_propagation off
void explosion_update(int obj)
{
    ExplosionPartfxSource fake;
    u16 ang[6];
    f32 vpos[3];
    f32 m[12];
    u8 rgb[3];
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    int p;
    lbl_803DDB58 += 1;
    p = state;
    ((ExplosionState*)state)->frameCounter += framesThisStep;
    for (i = 0, p = state; i < ((ExplosionState*)state)->flameCount; i++)
    {
        ((ExplosionDebris*)p)->unk10 += framesThisStep;
        if (((ExplosionDebris*)p)->unk2F != 0)
        {
            f32 sp = ((ExplosionDebris*)p)->unk1C;
            f32 ev = expf(
                (lbl_803E4934 * ((f32)(int)((ExplosionDebris*)p)->unk14 - (f32)(int)((ExplosionDebris*)p)->unk10)) / (
                    f32)(int)((ExplosionDebris*)p)->unk14);
            f32 d = sp - ((ExplosionDebris*)p)->unk18;
            f32 t = d * ev;
            ((ExplosionDebris*)p)->unkC = sp - lbl_803DDB70 * t;
            ev = expf((lbl_803E493C * (f32)(int)((ExplosionDebris*)p)->unk10) / (f32)(int)((ExplosionDebris*)p)->unk14);
            t = lbl_803E4938 * ev;
            *(s8*)&((ExplosionDebris*)p)->unk2E = lbl_803E4938 - lbl_803DDB6C * t;
            if (((ExplosionDebris*)p)->unk10 >= ((ExplosionDebris*)p)->unk14)
            {
                ((ExplosionDebris*)p)->unk2F = 0;
            }
            else
            {
                *(s16*)&((ExplosionDebris*)p)->unk28 += framesThisStep * *(s16*)&((ExplosionDebris*)p)->unk2A;
                if (((ExplosionDebris*)p)->unk2C >= 4)
                {
                    ((ExplosionDebris*)p)->unk2C -= 4;
                }
                if (((ExplosionDebris*)p)->unk2D < 5)
                {
                    if ((f32)(int)((ExplosionDebris*)p)->unk10 / (f32)(int)((ExplosionDebris*)p)->unk14 < lbl_803E4998
                        &&
                        (((ExplosionDebris*)p)->unk20 -= framesThisStep, ((ExplosionDebris*)p)->unk20 <= 0))
                    {
                        int st2;
                        u8 c;
                        f32 sp2;
                        f32 sv;
                        c = ((ExplosionDebris*)p)->unk2D;
                        sp2 = ((ExplosionDebris*)p)->unk1C;
                        st2 = *(int*)&((GameObject*)obj)->extra;
                        vpos[0] = ((ExplosionDebris*)p)->unkC * (lbl_803E495C * (f32)(int)
                        randomGetRange(-5, 3) + lbl_803E492C
                        )
                        ;
                        vpos[1] = lbl_803E4960;
                        vpos[2] = lbl_803E4960;
                        PSMTXRotRad(
                            m, 0x7a, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                        PSMTXConcat(Camera_GetInverseViewRotationMatrix(), m, m);
                        PSMTXMultVecSR(m, vpos, vpos);
                        vpos[0] += ((ExplosionDebris*)p)->unk0;
                        vpos[1] += ((ExplosionDebris*)p)->unk4;
                        vpos[2] += ((ExplosionDebris*)p)->unk8;
                        sv = sp2 * (f32)(int)
                        randomGetRange(0xc0, 0x100);
                        sv = sv * lbl_803E4974;
                        if (((ExplosionState*)st2)->flameCount < 0x32)
                        {
                            fn_801B3DE4(obj, (u8)(c + 1), sv, vpos[0], vpos[1], vpos[2]);
                        }
                        ((ExplosionDebris*)p)->unk20 = ((ExplosionDebris*)p)->unk24;
                    }
                }
            }
        }
        p += 0x30;
    }
    memcpy(&fake, (void*)obj, sizeof(fake));
    fake.rootMotionScale = lbl_803E492C;
    fake.velocityX = lbl_803E4960;
    fake.velocityY = lbl_803E4960;
    fake.velocityZ = lbl_803E4960;
    for (i = 0, p = state; i < ((ExplosionState*)state)->debrisCount; i++)
    {
        if (*(u8*)((char*)p + 0x984) != 0)
        {
            *(int*)((char*)p + 0x97c) += framesThisStep;
            if (*(int*)((char*)p + 0x97c) >= *(int*)((char*)p + 0x980))
            {
                *(u8*)((char*)p + 0x984) = 0;
            }
            else
            {
                f32 grav = ((ExplosionState*)state)->driftYSpeed;
                u32 ft = framesThisStep;
                f32 n974 = -(grav * (f32)(u32)
                ft - *(f32*)((char*)p + 0x974)
                )
                ;
                *(f32*)((char*)p + 0x968) = -(lbl_803E499C * (grav * (f32)(int)(ft * ft)) - (*(f32*)((char*)p + 0x974) *
                    (f32)(u32)
                ft + *(f32*)((char*)p + 0x968)
                )
                )
                ;
                *(f32*)((char*)p + 0x974) = n974;
                *(f32*)((char*)p + 0x964) += *(f32*)((char*)p + 0x970) * (f32)(u32)
                framesThisStep;
                *(f32*)((char*)p + 0x96c) += *(f32*)((char*)p + 0x978) * (f32)(u32)
                framesThisStep;
                if (*(u8*)&((ExplosionState*)state)->nearGround != 0 && *(f32*)((char*)p + 0x968) < ((ExplosionState*)state)->
                    groundY &&
                    *(f32*)((char*)p + 0x974) < lbl_803E4960)
                {
                    *(f32*)((char*)p + 0x974) = lbl_803E49A0 * -*(f32*)((char*)p + 0x974);
                }
                fake.localPosX = *(f32*)((char*)p + 0x964);
                fake.localPosY = *(f32*)((char*)p + 0x968);
                fake.localPosZ = *(f32*)((char*)p + 0x96c);
                fake.worldPosX = fake.localPosX;
                fake.worldPosY = fake.localPosY;
                fake.worldPosZ = fake.localPosZ;
                if (lbl_803DDB58 & 1)
                {
                    int t = *(int*)((char*)p + 0x97c);
                    if (t < 0x40)
                    {
                        int v = t << 6;
                        ang[0] = 0xffff - v;
                        ang[1] = ang[0];
                        ang[2] = 0x8000;
                        ang[3] = 0xc000 - v;
                        ang[4] = 0xa000 - v;
                        ang[5] = 0;
                    }
                    else if (t < 0x80)
                    {
                        int v = t << 6;
                        ang[0] = 0xc000 - v;
                        ang[1] = 0xa000 - v;
                        ang[2] = 0;
                        ang[3] = 0x8000;
                        ang[4] = 0;
                        ang[5] = 0;
                    }
                    else
                    {
                        ang[0] = 0xa000;
                        ang[1] = 0;
                        ang[2] = 0;
                        ang[3] = 0;
                        ang[4] = 0;
                        ang[5] = 0;
                    }
                    {
                        u8 md;
                        md = ((ExplosionState*)state)->modelKind;
                        switch (md)
                        {
                        case 0:
                            break;
                        case 1:
                            ang[1] = ang[2];
                            ang[4] = ang[5];
                            break;
                        case 2:
                            ang[1] = ang[0];
                            ang[4] = ang[3];
                            ang[0] = ang[2];
                            ang[3] = ang[5];
                            break;
                        case 3:
                        {
                            u16 sv5;
                            u16 sv = ang[2];
                            ang[1] = sv;
                            sv5 = ang[5];
                            ang[4] = sv5;
                            ang[2] = ang[0];
                            ang[5] = ang[3];
                            ang[0] = sv;
                            ang[3] = sv5;
                        }
                            break;
                        }
                    }
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x5e, &fake, 0x200001, -1, ang);
                }
            }
        }
        p += 0x24;
    }
    {
        int e = ((ExplosionState*)state)->frameCounter;
        int d = ((ExplosionState*)state)->lifeFrames;
        if (e > d << 1)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (e > d)
            {
                if (*(void**)&((ExplosionState*)state)->light != NULL)
                {
                    modelLightStruct_setEnabled(((ExplosionState*)state)->light, 0, lbl_803E4960);
                }
            }
            else
            {
                fn_801B40B8((f32)(int)e, (f32)(int)d, ((ExplosionState*)state)->modelKind, rgb);
                if (*(void**)&((ExplosionState*)state)->light != NULL)
                {
                    modelLightStruct_setDiffuseColor(((ExplosionState*)state)->light, rgb[0], rgb[1], rgb[2], 0xff);
                }
            }
            {
                f32 frac = (f32)(int)((ExplosionState*)state)->frameCounter / (f32)(int)((ExplosionState*)state)->
                    lifeFrames;
                ((GameObject*)obj)->anim.rootMotionScale = lbl_803E49A4 * (frac * ((ExplosionState*)state)->scale);
                ((GameObject*)obj)->anim.alpha = lbl_803E4938 - lbl_803E4938 * frac;
            }
            if (*(u8*)&((ExplosionState*)state)->halfLifeFired == 0 && ((ExplosionState*)state)->frameCounter >= (((
                ExplosionState*)state)->lifeFrames >> 1))
            {
                u32 k;
                u16 r0v = randomGetRange(0x1000, 0x6000);
                ang[0] = r0v;
                ang[1] = r0v;
                ang[2] = r0v;
                ang[3] = *(int*)((char*)state + 0x14);
                k = 0;
                while ((f32)(int)k < ((ExplosionState*)state)->scale
                )
                {
                    k++;
                }
                *(u8*)&((ExplosionState*)state)->halfLifeFired = 1;
            }
        }
    }
}
#pragma opt_propagation reset

void explosion_init(int obj, int p2)
{
    f32 vsp[3];
    f32 mB[12];
    f32 mA[12];
    int p;
    int state = *(int*)&((GameObject*)obj)->extra;
    f32 scale;
    int i;
    int n;
    ((ExplosionState*)state)->flameCount = 0;
    if (*(s16*)((char*)p2 + 0x1a) == 0)
    {
        scale = lbl_803E49A8;
    }
    else
    {
        scale = (f32)(int) * (s16*)((char*)p2 + 0x1a) * lbl_803E4974;
        if (scale > lbl_803E49A8)
        {
            scale = lbl_803E49A8;
        }
    }
    ((Fn801B3DE4SpdFirst)fn_801B3DE4)(obj, lbl_803E49AC * scale, 0, ((GameObject*)obj)->anim.localPosX,
                                      ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((ExplosionState*)state)->modelKind = *(s16*)((char*)p2 + 0x1c) & 3;
    Obj_SetActiveModelIndex(obj, ((ExplosionState*)state)->modelKind);
    if (*(s16*)((char*)p2 + 0x1c) & 4)
    {
        ((ExplosionState*)state)->driftYSpeed = lbl_803E49A4;
    }
    else
    {
        ((ExplosionState*)state)->driftYSpeed = lbl_803E4960;
    }
    *(u8*)&((ExplosionState*)state)->nearGround = 0;
    if (((HitDetectFloatsFirst)hitDetectFn_800658a4)(obj, ((GameObject*)obj)->anim.localPosX,
                             lbl_803E49B0 + ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ, state + 0x960, 0) == 0)
    {
        if (((ExplosionState*)state)->groundY < lbl_803E49B4)
        {
            *(u8*)&((ExplosionState*)state)->nearGround = 1;
        }
        ((ExplosionState*)state)->groundY = ((GameObject*)obj)->anim.localPosY - ((ExplosionState*)state)->groundY;
    }
    else
    {
        ((ExplosionState*)state)->groundY = ((GameObject*)obj)->anim.localPosY;
    }
    if (*(s16*)((char*)p2 + 0x1c) & 0x10)
    {
        n = (int)((f32)(lbl_803E49B8 * scale) / lbl_803E49A8);
        for (i = 0, p = state; i < n; i++)
        {
            if (*(u8*)&((ExplosionState*)state)->nearGround != 0)
            {
                f32 mag = (f32)(int)randomGetRange(0x14, 0x28) *lbl_803E49C0;
                mag = lbl_803E49BC * mag + lbl_803E49BC;
                vsp[0] = mag;
                vsp[1] = lbl_803E4960;
                vsp[2] = lbl_803E4960;
                PSMTXRotRad(
                    mB, 0x7a, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0x2000, 0x6000) / lbl_803E49C4)));
                PSMTXRotRad(mA, 0x79, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            }
            else
            {
                f32 mag = (f32)(int)randomGetRange(0x14, 0x28) *lbl_803E49C0;
                u8 idx = i % 4;
                mag = lbl_803E49BC * mag + lbl_803E49BC;
                vsp[0] = mag * lbl_80325528[idx * 3];
                vsp[1] = mag * lbl_80325528[idx * 3 + 1];
                vsp[2] = mag * lbl_80325528[idx * 3 + 2];
                PSMTXRotRad(mB, 0x7a, (f32)(
                                lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) /
                                lbl_803E49C4))
                )
                ;
                PSMTXRotRad(mA, 0x78, (f32)(
                                lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) /
                                lbl_803E49C4))
                )
                ;
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            }
            *(f32*)((char*)p + 0x964) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)p + 0x968) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)p + 0x96c) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)p + 0x970) = vsp[0];
            *(f32*)((char*)p + 0x974) = vsp[1];
            *(f32*)((char*)p + 0x978) = vsp[2];
            *(int*)((char*)p + 0x97c) = 0;
            *(int*)((char*)p + 0x980) = randomGetRange(0x28, 0x32);
            *(u8*)((char*)p + 0x984) = 1;
            p += 0x24;
        }
        ((ExplosionState*)state)->debrisCount = i;
    }
    else
    {
        ((ExplosionState*)state)->debrisCount = 0;
    }
    ((ExplosionState*)state)->light = 0;
    if (*(s16*)((char*)p2 + 0x1c) & 0x20)
    {
        ((ExplosionState*)state)->light = objCreateLight(0, 1);
        if (*(void**)&((ExplosionState*)state)->light != NULL)
        {
            modelLightStruct_setLightKind(((ExplosionState*)state)->light, 2);
            modelLightStruct_setPosition(((ExplosionState*)state)->light, ((GameObject*)obj)->anim.worldPosX,
                                         ((GameObject*)obj)->anim.worldPosY, ((GameObject*)obj)->anim.worldPosZ);
            modelLightStruct_setAffectsAabbLightSelection(((ExplosionState*)state)->light, 1);
            modelLightStruct_setEnabled(((ExplosionState*)state)->light, 1, lbl_803E4960);
            modelLightStruct_setDistanceAttenuation(((ExplosionState*)state)->light, (f32)(lbl_803E49CC * scale),
                                                    (f32)(lbl_803E4958 * scale));
            modelLightStruct_setDiffuseColor(((ExplosionState*)state)->light, 0xff, 0xeb, 0xa0, 0xff);
        }
    }
    ((GameObject*)obj)->anim.alpha = 0xff;
    if (*(s16*)((char*)p2 + 0x1c) & 8)
    {
        if (*(u8*)&((ExplosionState*)state)->nearGround == 0)
        {
            ((ExplosionState*)state)->rayMode = 2;
            *(u16*)&((ExplosionState*)state)->rayYawA = randomGetRange(0, 0x4000);
            *(u16*)&((ExplosionState*)state)->rayPitchA = randomGetRange(0, 0x8000);
            *(u16*)&((ExplosionState*)state)->rayYawB = *(u16*)&((ExplosionState*)state)->rayYawA + 0x4000;
            *(u16*)&((ExplosionState*)state)->rayPitchB = *(u16*)&((ExplosionState*)state)->rayPitchA;
        }
        else
        {
            ((ExplosionState*)state)->rayMode = 1;
            ((ExplosionState*)state)->rayYawA = 0;
            ((ExplosionState*)state)->rayPitchA = 0;
        }
    }
    else
    {
        ((ExplosionState*)state)->rayMode = 0;
    }
    *(u8*)&((ExplosionState*)state)->halfLifeFired = 0;
    ((ExplosionState*)state)->frameCounter = 0;
    ((ExplosionState*)state)->lifeFrames = (int)(lbl_803E4930 * sqrtf(scale));
    {
        int v = ((ExplosionState*)state)->lifeFrames;
        if (v < 0)
        {
            v = 0;
        }
        else if (v > 0x3c)
        {
            v = 0x3c;
        }
        ((ExplosionState*)state)->lifeFrames = v;
    }
    ((ExplosionState*)state)->scale = scale;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E4960;
}

void explosion_initialise(void)
{
    FbTexTbl t;
    int i;
    t = lbl_802C2328;
    lbl_803DDB70 = lbl_803E492C / expf(lbl_803E4934);
    lbl_803DDB6C = lbl_803E492C / expf(lbl_803E493C);
    lbl_803DDB68 = lbl_803E492C / expf(lbl_803E4958);
    lbl_803DDB64 = lbl_803E492C / expf(lbl_803E4950);
    lbl_803DDB60 = lbl_803E492C / expf(lbl_803E4954);
    lbl_803DDB5C = lbl_803E492C / expf(lbl_803E492C);
    for (i = 0; i < 4; i++)
    {
        lbl_803AC960[i] = textureLoadAsset(t.v[i]);
    }
}

void dimmagicbridge_updateVertexWave(int obj, u8* sub);
