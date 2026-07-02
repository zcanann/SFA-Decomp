/*
 * dll_1CE: hatch-door object. The lid coasts open under a clamped velocity
 * while idle; once a key object (seqId 0x18F or 0x1D6) is in range it counts
 * down, sets its placement gamebit, and - if the load isn't locked and the
 * placement's spawnGameBitValue matches gamebit 0x46D - spawns its contents object
 * (subtype 0x246) seeded from the door's transform.
 *
 * The TU also hosts dimmagicbridge_* and explosion_* sibling exports (in
 * DIM/dll_01CC_dimmagicbridge.c / DIM/dll_01CA_dimexplosion.c); their forward
 * declarations and the descriptor that combines them live in this object's DLL.
 */
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dll1ceplacement_struct.h"
#include "main/dll/fnexplosionreleasev11unusedstate_struct.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/explosion_state.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"

#define DLL1CE_OBJFLAG_HITDETECT_DISABLED 0x2000

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
 * pointers in update/render and stay untyped.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

extern u32 FUN_800067e8();
extern u32 FUN_80006824();
extern u32 FUN_80017924();
extern u32 FUN_80017944();
extern int FUN_80017a54();
extern u32 FUN_8002fc3c();
extern int FUN_80039520();
extern u32 FUN_80242114();
extern u64 FUN_80286834();
extern u32 FUN_8028683c();
extern u32 FUN_80286880();
extern u32 FUN_80286888();
extern u32 FUN_802924b4();
extern double FUN_80293900();
extern u32 FUN_80293f90();
extern u32 DAT_803dc070;
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
extern f32 lbl_803E49E8;
extern void* lbl_803DDB78;
extern f32 lbl_803E49F0;
extern f32 timeDelta;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void Obj_SetupObject(int* obj, int a, int b, int c, int d);
extern f32 lbl_803E49EC;
extern f32 lbl_803E49F4;
extern f32 lbl_803E49F8;
extern f32 lbl_803E49FC;

void FUN_801b3de4(u32 obj, u32 variant)
{
    (*gObjectTriggerInterface)->runSequence((variant ^ 1) + 2, (void*)obj, -1);
    return;
}

void FUN_801b40f0(u64 param_1, double param_2, double param_3, double param_4)
{
    u8 slotIdx;
    char stateByte;
    int lifetime;
    u32 obj;
    u8 extraout_r4;
    int sub4c;
    int state;
    int slotOff;
    int slot;
    double extraout_f1;
    double scale;
    double prevVal;

    obj = FUN_8028683c();
    sub4c = *(int *)&((GameObject *)obj)->anim.placementData;
    state = *(int *)&((GameObject *)obj)->extra;
    slotIdx = *(u8*)(state + 0xa58);
    *(u8*)(state + 0xa58) = slotIdx + 1;
    slotOff = slotIdx * 0x30;
    *(float*)(state + slotOff) = (float)param_2;
    slot = state + slotOff;
    *(float*)(slot + 4) = (float)param_3;
    *(float*)(slot + 8) = (float)param_4;
    *(float*)(slot + 0x18) = lbl_803E55C4;
    *(u32*)(slot + 0xc) = *(u32*)(state + 0x18);
    *(float*)(slot + 0x1c) = (float)extraout_f1;
    *(u8*)(slot + 0x2d) = extraout_r4;
    *(u32*)(slot + 0x10) = 0;
    scale = FUN_80293900(extraout_f1);
    *(int*)(slot + 0x14) = (int)((double)lbl_803E55C8 * scale);
    lifetime = *(int*)(slot + 0x14);
    if (lifetime < 0)
    {
        lifetime = 0;
    }
    else if (0x3c < lifetime)
    {
        lifetime = 0x3c;
    }
    *(int*)(slot + 0x14) = lifetime;
    if ((*(char*)(slot + 0x2d) != '\0') || (stateByte = *(char*)(sub4c + 0x19), stateByte == '\0'))
        goto LAB_801b44d4;
    if (stateByte == '\x02')
    {
        FUN_80006824(obj, 0x4bf);
        goto LAB_801b44d4;
    }
    if (stateByte == '\x03')
    {
        FUN_80006824(obj, 0x4c2);
        goto LAB_801b44d4;
    }
    stateByte = *(char*)(obj + 0xac);
    if (stateByte < ':')
    {
        if (stateByte == ',')
        {
        LAB_801b44b4:
            FUN_800067e8(obj, 0x4b8, 2);
            goto LAB_801b44d4;
        }
    }
    else if (stateByte < '?') goto LAB_801b44b4;
    FUN_80006824(obj, SFXthorntail_annoyed2);
LAB_801b44d4:
    obj = randomGetRange(0, 0xffff);
    *(short*)(state + slotOff + 0x28) = obj;
    obj = randomGetRange(200, 300);
    lifetime = state + slotOff;
    *(short*)(lifetime + 0x2a) = obj;
    obj = randomGetRange(0, 1);
    if (obj != 0)
    {
        *(short*)(lifetime + 0x2a) = -*(short*)(lifetime + 0x2a);
    }
    obj = randomGetRange(0, 3);
    *(char*)(state + slotOff + 0x2c) = obj;
    prevVal = (double)*(float*)(slot + 0x1c);
    scale = (double)FUN_802924b4();
    *(float*)(slot + 0xc) =
        -(float)((double)lbl_803DE7F0 *
            (double)(float)((double)(float)(prevVal - (double)*(float*)(slot + 0x18)) * scale)
            - prevVal);
    scale = (double)FUN_802924b4();
    state = state + slotOff;
    *(char*)(state + 0x2e) =
        (char)(int)-(float)((double)lbl_803DE7EC * (double)(float)((double)lbl_803E55D0 * scale)
            - (double)lbl_803E55D0);
    *(int*)(state + 0x20) = lbl_803E55D8;
    *(u32*)(state + 0x24) = *(u32*)(state + 0x20);
    *(u8*)(state + 0x2f) = 1;
    FUN_80286888();
    return;
}

void explosion_release(u32 obj);

void fn_explosion_release_v11_unused(u32 obj)
{
    short hitShapeId;
    float clampedSpeed;
    bool found;
    int count;
    int idx;
    char* state;
    short* placement;
    ObjHitsPriorityState* hitState;

    placement = *(short**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    FUN_8002fc3c((double)((FnExplosionReleaseV11UnusedState*)state)->unk4, (double)lbl_803DC074);
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + ((FnExplosionReleaseV11UnusedState
        *)state)->velZ;
    clampedSpeed = lbl_803E566C;
    if (((FnExplosionReleaseV11UnusedState*)state)->velZ != lbl_803E566C)
    {
        ((FnExplosionReleaseV11UnusedState*)state)->velZ = ((FnExplosionReleaseV11UnusedState*)state)->velZ *
            lbl_803E5670;
        if (((FnExplosionReleaseV11UnusedState*)state)->velZ < clampedSpeed)
        {
            clampedSpeed = ((FnExplosionReleaseV11UnusedState*)state)->velZ;
        }
        ((FnExplosionReleaseV11UnusedState*)state)->velZ = clampedSpeed;
    }
    if ((('\0' < *state) || (*placement != 0x338)) || (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E5674))
    {
        found = false;
        idx = 0;
        count = (int)*(char*)(*(int*)(obj + 0x58) + 0x10f);
        if (0 < count)
        {
            do
            {
                hitShapeId = *(short*)(*(int*)(*(int*)(obj + 0x58) + idx + 0x100) + 0x46);
                if ((hitShapeId == 399) || (hitShapeId == 0x1d6))
                {
                    found = true;
                    break;
                }
                idx = idx + 4;
                count = count + -1;
            }
            while (count != 0);
        }
        if (found)
        {
            ((FnExplosionReleaseV11UnusedState*)state)->unk4 = lbl_803E5678;
            ((FnExplosionReleaseV11UnusedState*)state)->velZ = lbl_803E567C;
            *state = '\0';
            GameBit_Set((int)placement[0xf], 1);
            FUN_80006824(obj, 0x3e1);
        }
    }
    else
    {
        count = (u32)((GameObject*)obj)->anim.alpha + DAT_803dc070 * -0x10;
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
    int obj;
    int* model;
    u16* outVtx;
    short* srcVtx;
    u32 fifoArg;
    int modelData;
    int i;
    u32 vtxCount;
    double rnd;
    u64 objHandle;
    u64 srcValPos;
    u64 srcValNeg;

    objHandle = FUN_80286834();
    obj = (int)((u64)objHandle >> 0x20);
    model = (int*)FUN_80017a54(obj);
    modelData = *model;
    for (i = 0; vtxCount = (u32) * (u16*)(modelData + 0xe4), i < vtxCount; i = i + 1)
    {
        outVtx = (u16*)FUN_80017944((int)model, i);
        srcVtx = (short*)FUN_80017924(modelData, i);
        if (*srcVtx < 1)
        {
            rnd = (double)FUN_80293f90();
            srcValNeg = (double)(int)*srcVtx;
            *outVtx = (short)(int)-(float)((double)lbl_803E569C * rnd -
                (double)(float)(srcValNeg));
        }
        else
        {
            rnd = (double)FUN_80293f90();
            srcValPos = (double)(int)*srcVtx;
            *outVtx = (short)(int)((double)lbl_803E569C * rnd +
                (double)(float)(srcValPos));
        }
    }
    fifoArg = FUN_80017944((int)model, 0);
    FUN_80242114(fifoArg, vtxCount * 6);
    ((GameObject*)obj)->anim.alpha = *(u8*)((int)objHandle + 0x51);
    FUN_80286880();
    return;
}

void FUN_801b5d00(int obj, int state)
{
    int channel;
    u32 phase;

    channel = FUN_80039520(obj, 0);
    *(short*)(channel + 10) = *(short*)(channel + 10) + 0x14;
    if (10000 < *(short*)(channel + 10))
    {
        *(short*)(channel + 10) = *(short*)(channel + 10) + -10000;
    }
    *(short*)(channel + 8) = *(short*)(channel + 8) + 10;
    if (10000 < *(short*)(channel + 8))
    {
        *(short*)(channel + 8) = *(short*)(channel + 8) + -10000;
    }
    channel = FUN_80039520(obj, 1);
    *(short*)(channel + 10) = *(short*)(channel + 10) + 0x1e;
    if (10000 < *(short*)(channel + 10))
    {
        *(short*)(channel + 10) = *(short*)(channel + 10) + -10000;
    }
    phase = (u32) * (u16*)(state + 0x60) + DAT_803dc070 * 0x100;
    if (0xffff < phase)
    {
        phase = phase - 0xffff;
    }
    *(short*)(state + 0x60) = phase;
    phase = (u32) * (u16*)(state + 0x62) + DAT_803dc070 * 0x80;
    if (0xffff < phase)
    {
        phase = phase - 0xffff;
    }
    *(short*)(state + 0x62) = phase;
    return;
}

void explosion_hitDetect(void);

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

int dll_1CE_getExtraSize(void) { return 0xc; }
int dll_1CE_getObjectTypeId(void) { return 0x0; }
int dimmagicbridge_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49E8);
}

void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

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

/* dimwooddoor2 variant: trigger-init that loads a different float
 * (lbl_803E49F0) into the extra block's [4]. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

#pragma scheduling off
#pragma peephole off
void dll_1CE_init(u8* obj, u8* params)
{
    Dll1CEState* sub;
    ObjHitsPriorityState* hitState;
    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8
    )
    ;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DLL1CE_OBJFLAG_HITDETECT_DISABLED);
    sub = ((GameObject*)obj)->extra;
    sub->igniteCountdown = 1;
    if (GameBit_Get(((Dll1CEPlacement*)params)->gameBitId) != 0)
    {
        sub->igniteCountdown = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
    }
    sub->openVelocity = lbl_803E49F0;
}

void explosion_free(int obj);

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
#pragma dont_inline on
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

/* EN v1.0 0x801B5AA0  size: 496b  dll_1CE_update: hatch-door logic - coast
 * the lid open with clamped velocity while idle, and once a key object is
 * nearby, count down then ring the gamebit and (if the load isn't locked)
 * spawn the contents object seeded from the door's transform. */
#pragma opt_strength_reduction off
void dll_1CE_update(int* obj)
{
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
    Dll1CEState* sub = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    if (((GameObject*)obj)->anim.alpha == 0) return;
    if ((s8)sub->igniteCountdown <= 0)
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
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
        int off;
        int i;
        int* list;
        int n;
        int found = 0;
        off = 0;
        list = *(int**)((char*)obj + 0x58);
        n = (s8) * (s8*)((char*)list + 0x10f);
        for (i = 0; i < n; i++)
        {
            int* o = *(int**)((char*)list + off + 0x100);
            if (*(s16*)((char*)o + 0x46) == 0x18f || *(s16*)((char*)o + 0x46) == 0x1d6)
            {
                found = 1;
                break;
            }
            off += 4;
        }
        if (!found) return;
    }
    {
        if ((s8)(sub->igniteCountdown -= 1) > 0) return;
    }
    GameBit_Set(((Dll1CEPlacement*)q)->gameBitId, 1);
    sub->opened = 1;
    if ((u32)(s16)((Dll1CEPlacement*)q)->spawnGameBitValue != GameBit_Get(0x46d)) return;
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
        *(u8*)((char*)no + 0x1b) = (u8)((s16)((GameObject*)obj)->anim.rotX >> 8);
        Obj_SetupObject(no, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    }
}
#pragma opt_strength_reduction reset

FbWGPipe GXWGFifo : (0xCC008000);
