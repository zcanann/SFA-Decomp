/* DLL 0x00FD — baby CloudRunner objects [8017EF6C-8017EFF0) */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objlib.h"
#include "main/dll/dll_00FD.h"
#include "main/game_ui_interface.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"

#define DLL00FD_OBJFLAG_HIDDEN 0x4000
extern void objRenderFn_80041018(void);
extern f32 lbl_803E3850;
extern void objRenderFn_8003b8f4(f32);


extern void Sfx_StopObjectChannel(int obj, int channel);
extern s16 getAngle(f32 dx, f32 dz);


extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern f32 lbl_803E3854;
extern f32 lbl_803E3858;
extern f32 lbl_803E385C;
extern f32 lbl_803E3870;
extern f32 lbl_803E3874;
extern f32 lbl_803E3878;
extern f32 lbl_803E387C;
extern f32 lbl_803E3880;
extern void dll_14D_update();
extern void dll_14D_free_nop();

void dll_14D_hitDetect(int obj)
{
    if (((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0) &&
        (((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL))
    {
        objRenderFn_80041018();
    }
    return;
}

void dll_14D_free_nop(void)
{
}

int dll_14D_getExtraSize_ret_8(void) { return 0x8; }
int dll_14D_getObjectTypeId(void) { return 0x0; }

void dll_14D_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3850);
}

typedef struct Dll14DState
{
    u8 mode;       /* 0x00: state-machine mode (0/1/2/3/4) */
    u8 gateOpen;   /* 0x01: GameBit-gated flag (0/1) */
    u8 pad02[2];
    u32 anchorObj; /* 0x04: nearest object (ObjGroup_FindNearestObject); this object snaps to its pos/rot */
} Dll14DState;

STATIC_ASSERT(offsetof(Dll14DState, anchorObj) == 0x4);
STATIC_ASSERT(sizeof(Dll14DState) == 0x8);

/* Class-specific placement record for the dll_14D (baby-CloudRunner trigger)
 * family: ObjPlacement common head (0x00..0x17) + trigger/sequence fields. */
typedef struct Dll14DPlacement
{
    ObjPlacement head;     /* 0x00..0x17 */
    s16 enableBit;         /* 0x18: GameBit gating activation */
    s16 stateBit;          /* 0x1a: GameBit persisting open/closed state */
    s16 eventId;           /* 0x1c: UI event id to wait on */
    s16 preemptSeq;        /* 0x1e: sequence id passed to preempt() */
    u8 runSeqArg;          /* 0x20: runSequence 3rd arg */
    u8 groupId;            /* 0x21: ObjGroup_FindNearestObject group id */
    u8 runSeqId;           /* 0x22: runSequence sequence id */
    u8 flags;              /* 0x23: bit0 = no auto-open, bit1 = clear enableBit */
} Dll14DPlacement;

STATIC_ASSERT(offsetof(Dll14DPlacement, enableBit) == 0x18);
STATIC_ASSERT(offsetof(Dll14DPlacement, flags) == 0x23);
STATIC_ASSERT(sizeof(Dll14DPlacement) == 0x24);

typedef struct MagicPlantBridgeState
{
    int childObj;
    f32 moveProgress;
    f32 moveStepScale;
    s16 timer;
    u8 pad0E;
    s8 mode;
} MagicPlantBridgeState;

void dll_14D_update(u16* obj)
{
    extern u32 ObjGroup_FindNearestObject(); /* #57 */
    u8 mode;
    u32 found;
    u32 bitVal;
    int eventReady;
    Dll14DPlacement* placement;
    Dll14DState* state;
    float dist;

    dist = lbl_803E3854;
    placement = (Dll14DPlacement*)((GameObject*)obj)->anim.placementData;
    state = (Dll14DState*)((GameObject*)obj)->extra;
    if (*(void**)&state->anchorObj == NULL)
    {
        found = ObjGroup_FindNearestObject((u32)placement->groupId, obj, &dist);
        state->anchorObj = found;
        if (*(void**)&state->anchorObj == NULL)
        {
            return;
        }
        if (placement->stateBit == -1)
        {
            state->gateOpen = 0;
        }
        else
        {
            bitVal = GameBit_Get(placement->stateBit);
            state->gateOpen = bitVal;
        }
        if ((state->gateOpen != 0) && (placement->preemptSeq != -1))
        {
            state->mode = 1;
        }
        else
        {
            state->mode = 2;
        }
    }
    ((GameObject*)obj)->anim.localPosX = *(f32*)(state->anchorObj + 0xc);
    ((GameObject*)obj)->anim.localPosY = *(f32*)(state->anchorObj + 0x10);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)(state->anchorObj + 0x14);
    ((GameObject*)obj)->anim.rotX = *(s16*)state->anchorObj;
    ((GameObject*)obj)->anim.rotZ = *(s16*)(state->anchorObj + 4);
    ((GameObject*)obj)->anim.rotY = *(s16*)(state->anchorObj + 2);
    mode = state->mode;
    switch (mode)
    {
    case 1:
        *(u8*)(state->anchorObj + 0xaf) &= ~0x20;
        *(u8*)((int)obj + 0xaf) |= 8;
        (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptSeq);
        (*gObjectTriggerInterface)->runSequence(placement->runSeqId, obj,
                                                placement->runSeqArg);
        state->mode = 4;
        break;
    case 2:
        if ((state->gateOpen != 0) && ((placement->flags & 1) == 0))
        {
            *(u8*)(state->anchorObj + 0xaf) &= ~0x20;
            *(u8*)((int)obj + 0xaf) |= 8;
            state->mode = 4;
        }
        else if ((placement->enableBit != -1) &&
            (bitVal = GameBit_Get(placement->enableBit), bitVal == 0))
        {
            *(u8*)(state->anchorObj + 0xaf) &= ~0x20;
            *(u8*)((int)obj + 0xaf) |= 8;
            state->mode = 3;
        }
        else if (((*(u8*)((int)obj + 0xaf) & 1) != 0) &&
            ((placement->eventId == -1) ||
                (eventReady = (*gGameUIInterface)->isEventReady(placement->eventId),
                    eventReady != 0)))
        {
            if ((placement->flags & 2) != 0)
            {
                GameBit_Set(placement->enableBit, 0);
            }
            if (placement->stateBit != -1)
            {
                GameBit_Set(placement->stateBit, 1);
            }
            *(u8*)((int)obj + 0xaf) |= 8;
            state->gateOpen = 1;
            (*gObjectTriggerInterface)->runSequence(placement->runSeqId, obj,
                                                    0xffffffff);
        }
        else
        {
            *(u8*)(state->anchorObj + 0xaf) |= 0x20;
            *(u8*)((int)obj + 0xaf) &= ~8;
        }
        break;
    case 3:
        bitVal = GameBit_Get(placement->enableBit);
        if (bitVal != 0)
        {
            state->mode = 2;
        }
        break;
    case 4:
        break;
    }
}

void dll_14D_init(int* obj)
{
    Dll14DState* p = ((GameObject*)obj)->extra;
    p->mode = 0;
    p->anchorObj = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DLL00FD_OBJFLAG_HIDDEN);
}

void fn_8017F334(int obj, void* setup, void* stateArg)
{
    MagicPlantBridgeState* state;
    int player;
    u8* childObj;
    f32 launchSpeed;
    s16 angle;

    state = (MagicPlantBridgeState*)stateArg;
    player = (int)Obj_GetPlayerObject();
    Sfx_StopObjectChannel(obj, 0x40);

    childObj = *(u8**)&state->childObj;
    if ((childObj != NULL) && (*(void**)(childObj + 0xc4) != NULL) &&
        (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3870))
    {
        state->childObj = 0;
        ObjLink_DetachChild(obj, (int)childObj);

        launchSpeed = (f32)(int)
        randomGetRange(0x27, 0x2c) / lbl_803E3874;
        angle = getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX,
                         ((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ);
        randomGetRange(((u16)angle) - 0x1000, ((u16)angle) + 0x1000);

        ((GameObject*)childObj)->anim.velocityX =
            launchSpeed * mathSinf((lbl_803E3878 * (f32) * (s16*)obj) / lbl_803E387C);
        ((GameObject*)childObj)->anim.velocityZ =
            launchSpeed * mathCosf((lbl_803E3878 * (f32) * (s16*)obj) / lbl_803E387C);
        Sfx_PlayFromObject(obj, 0x5e);
    }

    if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3858)
    {
        state->mode = 2;
        state->moveStepScale = lbl_803E3880;
        ObjAnim_SetCurrentMove(obj, 2, lbl_803E385C, 0);
    }
}

void dll_14D_release_nop(void)
{
}

void dll_14D_initialise_nop(void)
{
}

ObjectDescriptor gDll14DObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_14D_initialise_nop,
    (ObjectDescriptorCallback)dll_14D_release_nop,
    0,
    (ObjectDescriptorCallback)dll_14D_init,
    (ObjectDescriptorCallback)dll_14D_update,
    (ObjectDescriptorCallback)dll_14D_hitDetect,
    (ObjectDescriptorCallback)dll_14D_render,
    (ObjectDescriptorCallback)dll_14D_free_nop,
    (ObjectDescriptorCallback)dll_14D_getObjectTypeId,
    dll_14D_getExtraSize_ret_8,
};
