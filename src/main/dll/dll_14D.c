#include "main/dll/dll_14D.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

typedef struct Dll14DState
{
    u8 pad0[0x4 - 0x0];
    u32 unk4;
} Dll14DState;


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern void* Obj_GetPlayerObject(void);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void ObjLink_DetachChild(int obj, int childObj);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 lbl_803E3854;
extern f32 lbl_803E44E4;
extern f32 lbl_803E3858;
extern f32 lbl_803E385C;
extern f64 lbl_803E3860;
extern f32 lbl_803E3870;
extern f32 lbl_803E3874;
extern f32 lbl_803E3878;
extern f32 lbl_803E387C;
extern f32 lbl_803E3880;

typedef struct MagicPlantBridgeState
{
    int childObj;
    f32 moveProgress;
    f32 moveStepScale;
    s16 timer;
    u8 pad0E;
    s8 mode;
} MagicPlantBridgeState;

/*
 * --INFO--
 *
 * Function: dll_14D_update
 * EN v1.0 Address: 0x8017EFF0
 * EN v1.0 Size: 632b
 * EN v1.1 Address: 0x8017F1EC
 * EN v1.1 Size: 748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_14D_update(undefined2* obj)
{
    byte mode;
    undefined4 found;
    uint bitVal;
    int eventReady;
    int placement;
    byte* state;
    float dist;

    dist = lbl_803E3854;
    placement = *(int*)(obj + 0x26);
    state = *(byte**)(obj + 0x5c);
    if (*(void**)(state + 4) == NULL)
    {
        found = ObjGroup_FindNearestObject((uint) * (byte*)(placement + 0x21), obj, &dist);
        *(undefined4*)(state + 4) = found;
        if (*(void**)(state + 4) == NULL)
        {
            return;
        }
        if (*(s16*)(placement + 0x1a) == -1)
        {
            state[1] = 0;
        }
        else
        {
            bitVal = GameBit_Get(*(s16*)(placement + 0x1a));
            state[1] = (byte)bitVal;
        }
        if ((state[1] != 0) && (*(s16*)(placement + 0x1e) != -1))
        {
            *state = 1;
        }
        else
        {
            *state = 2;
        }
    }
    *(f32*)(obj + 6) = *(f32*)(*(int*)(state + 4) + 0xc);
    *(f32*)(obj + 8) = *(f32*)(*(int*)(state + 4) + 0x10);
    *(f32*)(obj + 10) = *(f32*)(*(int*)(state + 4) + 0x14);
    *(s16*)obj = **(s16**)(state + 4);
    *(s16*)(obj + 2) = *(s16*)(*(int*)(state + 4) + 4);
    *(s16*)(obj + 1) = *(s16*)(*(int*)(state + 4) + 2);
    mode = *state;
    switch (mode)
    {
    case 1:
        *(byte*)(*(int*)(state + 4) + 0xaf) &= ~0x20;
        *(byte*)((int)obj + 0xaf) |= 8;
        (*gObjectTriggerInterface)->preempt((int)obj, *(s16*)(placement + 0x1e));
        (*gObjectTriggerInterface)->runSequence(*(byte*)(placement + 0x22), obj,
                                                *(byte*)(placement + 0x20));
        *state = 4;
        break;
    case 2:
        if ((state[1] != 0) && ((*(byte*)(placement + 0x23) & 1) == 0))
        {
            *(byte*)(*(int*)(state + 4) + 0xaf) &= ~0x20;
            *(byte*)((int)obj + 0xaf) |= 8;
            *state = 4;
        }
        else if ((*(s16*)(placement + 0x18) != -1) &&
            (bitVal = GameBit_Get(*(s16*)(placement + 0x18)), bitVal == 0))
        {
            *(byte*)(*(int*)(state + 4) + 0xaf) &= ~0x20;
            *(byte*)((int)obj + 0xaf) |= 8;
            *state = 3;
        }
        else if (((*(byte*)((int)obj + 0xaf) & 1) != 0) &&
            ((*(s16*)(placement + 0x1c) == -1) ||
                (eventReady = (*gGameUIInterface)->isEventReady(*(s16*)(placement + 0x1c)),
                    eventReady != 0)))
        {
            if ((*(byte*)(placement + 0x23) & 2) != 0)
            {
                GameBit_Set(*(s16*)(placement + 0x18), 0);
            }
            if (*(s16*)(placement + 0x1a) != -1)
            {
                GameBit_Set(*(s16*)(placement + 0x1a), 1);
            }
            *(byte*)((int)obj + 0xaf) |= 8;
            state[1] = 1;
            (*gObjectTriggerInterface)->runSequence(*(byte*)(placement + 0x22), obj,
                                                    0xffffffff);
        }
        else
        {
            *(byte*)(*(int*)(state + 4) + 0xaf) |= 0x20;
            *(byte*)((int)obj + 0xaf) &= ~8;
        }
        break;
    case 3:
        bitVal = GameBit_Get(*(s16*)(placement + 0x18));
        if (bitVal != 0)
        {
            *state = 2;
        }
        break;
    case 4:
        break;
    }
}

/*
 * --INFO--
 *
 * Function: dll_14D_init
 * EN v1.0 Address: 0x8017F308
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017F4D8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_14D_init(int* obj)
{
    char* p = ((GameObject*)obj)->extra;
    *p = 0;
    ((Dll14DState*)p)->unk4 = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
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
        angle = getAngle(((GameObject*)obj)->anim.localPosX - *(f32*)(player + 0x0c),
                         ((GameObject*)obj)->anim.localPosZ - *(f32*)(player + 0x14));
        randomGetRange(((u16)angle) - 0x1000, ((u16)angle) + 0x1000);

        *(f32*)(childObj + 0x24) =
            launchSpeed * mathSinf((lbl_803E3878 * (f32) * (s16*)obj) / lbl_803E387C);
        *(f32*)(childObj + 0x2c) =
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


/* Trivial 4b 0-arg blr leaves. */
void dll_14D_release_nop(void)
{
}

void dll_14D_initialise_nop(void)
{
}

extern void dll_14D_update();
extern void dll_14D_hitDetect(int param_1);
extern void dll_14D_render(int p1, int p2, int p3, int p4, s8 visible);
extern void dll_14D_free_nop();
extern int dll_14D_getObjectTypeId(void);
extern int dll_14D_getExtraSize_ret_8(void);

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
