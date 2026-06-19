/*
 * magiclight (DLL 0x16B) - proximity-triggered "magic light" object, plus
 * the sibling event objects that share this translation unit (dll_16C
 * map-event proxy, imicemountain, crrockfall).
 *
 * magiclight: seqId 0x172 is a render-only variant (draws a glow each
 * visible frame). The other variants carry a MagicLightState: at init a
 * random lifetime is rolled and, for seqId 0x16B, the placement subtype
 * picks an enter/leave L-action pair and a trigger radius preset. Each
 * tick (magiclight_SeqFn) the distance to the player is measured: crossing
 * inside triggerRadius fires the enter action, crossing back outside the
 * radius plus hysteresis fires the leave action. magiclight_update kicks
 * off trigger sequence 0 once, on the first update.
 *
 * The FUN_* functions are still-raw Ghidra output banked pending cleanup:
 * FUN_801ac248 = imicemountain_updateEventState, FUN_801ad984 = dll_16C_SeqFn,
 * FUN_801adca0 = dll_16C_render, FUN_801addec = dll_16C_update.
 */
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMboulder.h"
#include "main/sfa_shared_decls.h"

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

STATIC_ASSERT(sizeof(Dll16CState) == 0x24);

STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);

extern u32 getLActions();
extern u32 FUN_8001771c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern u32 FUN_80017ac8();
extern u32 FUN_80017ae4();
extern u32 FUN_80017ae8();
extern u32 FUN_800305f8();
extern u32 DAT_802c2a88;
extern u32 DAT_802c2a8c;
extern u32 DAT_802c2a90;
extern f32 lbl_803E53D0;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53F0;
extern int randomGetRange(int lo, int hi);
extern f32 lbl_803E4740;
extern f32 lbl_803E4744;
extern f32 lbl_803E473C;
extern void objRenderFn_8003b8f4(f32);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_803E4738;

extern void Music_Trigger(int id, int arg);

void FUN_801ac248(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  int param_9)
{
}

u32
FUN_801ad984(u64 param_1, u64 param_2, double param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, int param_9)
{
    int lookupBase;
    u32 in_r9;
    u32 in_r10;
    float* state;
    double dist;
    double value;

    if (((GameObject*)param_9)->anim.seqId != 0x172)
    {
        state = ((GameObject*)param_9)->extra;
        lookupBase = FUN_80017a98();
        dist = (double)FUN_8001771c((float*)(lookupBase + 0x18), (float*)&((GameObject*)param_9)->anim.worldPosX);
        value = (double)*state;
        if ((value <= dist) || (*(char*)((int)state + 0xb) != '\0'))
        {
            if (((double)(float)((double)lbl_803E53D0 + value) < dist) &&
                (*(char*)((int)state + 0xb) != '\0'))
            {
                *(u8*)((int)state + 0xb) = 0;
                getLActions(dist, value, param_3, param_4, param_5, param_6, param_7, param_8, param_9, param_9,
                            (u32) * (u16*)(state + 2), 0, 0, 0, in_r9, in_r10);
            }
        }
        else
        {
            *(u8*)((int)state + 0xb) = 1;
            getLActions(dist, value, param_3, param_4, param_5, param_6, param_7, param_8, param_9, param_9,
                        (u32) * (u16*)((int)state + 6), 0, 0, 0, in_r9, in_r10);
        }
    }
    return 0;
}

void FUN_801adca0(u16* param_1, u16* param_2, u32 param_3, u32 param_4,
                  u32 param_5, u32 param_6, char param_7, int param_8, int param_9)
{
    u8 savedAlpha;
    u32 local_28;
    u32 local_24;
    u32 local_20[5];

    if (((param_9 != 0) && (param_7 != '\0')) && (0 < param_8))
    {
        savedAlpha = *(u8*)((int)param_2 + 0x37);
        *(char*)((int)param_2 + 0x37) = param_8;
        (**(VtableFn**)(**(int**)(param_2 + 0x34) + 0x10))
            (param_2, param_3, param_4, param_5, param_6, 0xffffffff);
        *(u8*)((int)param_2 + 0x37) = savedAlpha;
    }
    *(u32*)(param_1 + 0x46) = *(u32*)(param_1 + 0xc);
    *(u32*)(param_1 + 0x48) = *(u32*)(param_1 + 0xe);
    *(u32*)(param_1 + 0x4a) = *(u32*)(param_1 + 0x10);
    *(u32*)(param_1 + 0x40) = *(u32*)(param_1 + 6);
    *(u32*)(param_1 + 0x42) = *(u32*)(param_1 + 8);
    *(u32*)(param_1 + 0x44) = *(u32*)(param_1 + 10);
    (**(VtableFn**)(**(int**)(param_2 + 0x34) + 0x28))(param_2, local_20, &local_24, &local_28);
    *(u32*)(param_1 + 6) = local_20[0];
    *(u32*)(param_1 + 8) = local_24;
    *(u32*)(param_1 + 10) = local_28;
    *param_1 = *param_2;
    param_1[1] = param_2[1];
    param_1[2] = param_2[2];
    *(u32*)(param_1 + 0xc) = *(u32*)(param_1 + 6);
    *(u32*)(param_1 + 0xe) = *(u32*)(param_1 + 8);
    *(u32*)(param_1 + 0x10) = *(u32*)(param_1 + 10);
    *(u32*)(param_1 + 0x12) = *(u32*)(param_2 + 0x12);
    *(u32*)(param_1 + 0x14) = *(u32*)(param_2 + 0x14);
    *(u32*)(param_1 + 0x16) = *(u32*)(param_2 + 0x16);
    return;
}

u32
FUN_801addec(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, int param_9, u32 param_10
             , ObjAnimUpdateState* param_11, u32 param_12, u32* param_13, u32 param_14, u32 param_15
             , u32 param_16)
{
    u32 active;
    u16* setup;
    u32 spawned;
    int modelState;
    int* extra;
    int linkedObj;
    u16 uStack_2a;
    u32 local_28;
    u32 local_24;
    u16 local_20;

    extra = ((GameObject*)param_9)->extra;
    *(u8*)(extra + 8) = 0xff;
    linkedObj = *extra;
    if (param_11->triggerCommand == 3)
    {
        *(u8*)((int)extra + 0x21) = 0xff;
        param_11->triggerCommand = 0;
    }
    local_28 = DAT_802c2a88;
    local_24 = DAT_802c2a8c;
    local_20 = DAT_802c2a90;
    if (*(char*)((int)extra + 0x21) != *(char*)((int)extra + 0x22))
    {
        if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
        {
            param_1 = FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                   *(int*)&((GameObject*)param_9)->childObjs[0]);
            *(u32*)(param_9 + 200) = 0;
            *(u8*)(param_9 + 0xeb) = 0;
        }
        active = FUN_80017ae8();
        if ((active & 0xff) == 0)
        {
            *(u8*)((int)extra + 0x22) = 0;
        }
        else
        {
            if (0 < *(char*)((int)extra + 0x21))
            {
                setup = FUN_80017aa4(0x18, (&uStack_2a)[*(char*)((int)extra + 0x21)]);
                param_12 = 0xffffffff;
                param_13 = *(u32**)&((GameObject*)param_9)->anim.parent;
                spawned = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, setup,
                                     4, 0xff, 0xffffffff, param_13, param_14, param_15, param_16);
                *(u32*)(param_9 + 200) = spawned;
                *(u8*)(param_9 + 0xeb) = 1;
            }
            *(u8*)((int)extra + 0x22) = *(u8*)((int)extra + 0x21);
        }
    }
    param_11->hitVolumePair = param_11->activeHitVolumePair;
    if ((linkedObj == 0) || (param_11->triggerCommand != 2))
    {
        if ((linkedObj != 0) && (param_11->triggerCommand == 1))
        {
            (**(VtableFn**)(**(int**)(linkedObj + 0x68) + 0x3c))(linkedObj, 0);
            param_11->triggerCommand = 0;
        }
    }
    else
    {
        extra[1] = lbl_803E53F0;
        extra[2] = extra[5];
        extra[3] = extra[6];
        extra[4] = extra[7];
        (**(VtableFn**)(**(int**)(linkedObj + 0x68) + 0x3c))(linkedObj, 2);
        FUN_800305f8((double)lbl_803E53E0, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0x100, 1, param_12, param_13, param_14, param_15, param_16);
        modelState = (int)((GameObject*)param_9)->anim.modelState;
        if (modelState != 0)
        {
            ((GameObject*)param_9)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        param_11->hitVolumePair &= ~4;
        param_11->triggerCommand = 0;
    }
    if ((linkedObj != 0) && (linkedObj = (**(VtableFn**)(**(int**)(linkedObj + 0x68) + 0x38))(linkedObj), linkedObj == 2))
    {
        param_11->hitVolumePair &= 0xfffc;
    }
    return 0;
}

void magiclight_hitDetect(void)
{
}

void magiclight_release(void)
{
}

void magiclight_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void magiclight_init(int* obj, u8* params)
{
    MagicLightState* state;
    ((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = magiclight_SeqFn;
    if (((GameObject*)obj)->anim.seqId == 0x172)
    {
        return;
    }
    state = ((GameObject*)obj)->extra;
    state->lifetime = randomGetRange(0xc8, 0x258);
    state->subtype = (s8) * (s16*)(params + 0x1a);
    state->inRange = 0;
    if (((GameObject*)obj)->anim.seqId == 0x16b)
    {
        switch (state->subtype)
        {
        case 0:
            state->enterAction = 0x90;
            state->leaveAction = 0x91;
            state->triggerRadius = lbl_803E4740;
            break;
        case 1:
            state->enterAction = 0x92;
            state->leaveAction = 0x93;
            state->triggerRadius = lbl_803E4740;
            break;
        default:
            state->enterAction = 0x94;
            state->leaveAction = 0x95;
            state->triggerRadius = lbl_803E4744;
            break;
        case 3:
            state->enterAction = 0x187;
            state->leaveAction = 0x5;
            state->triggerRadius = lbl_803E4740;
            break;
        }
        state->unk10 = 0x12d;
    }
    else
    {
        state->unk10 = 0x12d;
    }
}

int magiclight_getObjectTypeId(void) { return 0x0; }

/* peephole stays off (from magiclight_init) for every function below: the
   target was built that way and restoring it regresses the rest of the TU. */
#pragma scheduling on
void magiclight_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (((GameObject*)obj)->anim.seqId == 0x172 && visible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E473C);
    }
}

#pragma scheduling off
void magiclight_free(int obj)
{
    MagicLightState* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId != 0x172)
    {
        if ((s8)state->inRange != 0)
        {
            getLActions(obj, obj, (u16)state->leaveAction, 0, 0, 0);
        }
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
}

void magiclight_update(int obj)
{
    if (((GameObject*)obj)->anim.seqId != 0x172 && ((GameObject*)obj)->unkF4 == 0)
    {
        ((GameObject*)obj)->anim.rotX = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ((GameObject*)obj)->unkF4 = 1;
    }
}

#pragma scheduling on
int magiclight_getExtraSize(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x172) return 0x0;
    return 0x14;
}

#pragma scheduling off
int magiclight_SeqFn(int* obj)
{
    MagicLightState* state;
    int* player;
    f32 dist;

    if (((GameObject*)obj)->anim.seqId == 0x172) return 0;

    state = ((GameObject*)obj)->extra;
    player = (int*)Obj_GetPlayerObject();
    dist = Vec_distance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);

    if (dist < state->triggerRadius && state->inRange == 0)
    {
        state->inRange = 1;
        getLActions(obj, obj, (u16)state->enterAction, 0, 0, 0);
    }
    else if (dist > lbl_803E4738 + state->triggerRadius && state->inRange != 0)
    {
        state->inRange = 0;
        getLActions(obj, obj, (u16)state->leaveAction, 0, 0, 0);
    }
    return 0;
}
#pragma scheduling on
#pragma peephole on
