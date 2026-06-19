/* DLL 0x00FD — baby CloudRunner objects [8017EF6C-8017EFF0) */
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/dll/dll_00FD.h"
#include "main/game_ui_interface.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
extern void objRenderFn_80041018(void);
extern f32 lbl_803E3850;
extern void objRenderFn_8003b8f4(f32);
extern int randomGetRange(int lo, int hi);

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

void dll_14D_hitDetect(int param_1)
{
    if (((((ObjAnimComponent*)param_1)->modelInstance->flags & 1) != 0) &&
        (((ObjAnimComponent*)param_1)->hitVolumeTransforms != NULL))
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
    u8 pad0[0x4 - 0x0];
    u32 unk4;
} Dll14DState;

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
    int placement;
    u8* state;
    float dist;

    dist = lbl_803E3854;
    placement = *(int*)(obj + 0x26);
    state = *(u8**)(obj + 0x5c);
    if (*(void**)(state + 4) == NULL)
    {
        found = ObjGroup_FindNearestObject((u32) * (u8*)(placement + 0x21), obj, &dist);
        *(u32*)(state + 4) = found;
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
            state[1] = bitVal;
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
    ((GameObject*)obj)->anim.localPosX = *(f32*)(*(int*)(state + 4) + 0xc);
    ((GameObject*)obj)->anim.localPosY = *(f32*)(*(int*)(state + 4) + 0x10);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)(*(int*)(state + 4) + 0x14);
    ((GameObject*)obj)->anim.rotX = **(s16**)(state + 4);
    ((GameObject*)obj)->anim.rotZ = *(s16*)(*(int*)(state + 4) + 4);
    ((GameObject*)obj)->anim.rotY = *(s16*)(*(int*)(state + 4) + 2);
    mode = *state;
    switch (mode)
    {
    case 1:
        *(u8*)(*(int*)(state + 4) + 0xaf) &= ~0x20;
        *(u8*)((int)obj + 0xaf) |= 8;
        (*gObjectTriggerInterface)->preempt((int)obj, *(s16*)(placement + 0x1e));
        (*gObjectTriggerInterface)->runSequence(*(u8*)(placement + 0x22), obj,
                                                *(u8*)(placement + 0x20));
        *state = 4;
        break;
    case 2:
        if ((state[1] != 0) && ((*(u8*)(placement + 0x23) & 1) == 0))
        {
            *(u8*)(*(int*)(state + 4) + 0xaf) &= ~0x20;
            *(u8*)((int)obj + 0xaf) |= 8;
            *state = 4;
        }
        else if ((*(s16*)(placement + 0x18) != -1) &&
            (bitVal = GameBit_Get(*(s16*)(placement + 0x18)), bitVal == 0))
        {
            *(u8*)(*(int*)(state + 4) + 0xaf) &= ~0x20;
            *(u8*)((int)obj + 0xaf) |= 8;
            *state = 3;
        }
        else if (((*(u8*)((int)obj + 0xaf) & 1) != 0) &&
            ((*(s16*)(placement + 0x1c) == -1) ||
                (eventReady = (*gGameUIInterface)->isEventReady(*(s16*)(placement + 0x1c)),
                    eventReady != 0)))
        {
            if ((*(u8*)(placement + 0x23) & 2) != 0)
            {
                GameBit_Set(*(s16*)(placement + 0x18), 0);
            }
            if (*(s16*)(placement + 0x1a) != -1)
            {
                GameBit_Set(*(s16*)(placement + 0x1a), 1);
            }
            *(u8*)((int)obj + 0xaf) |= 8;
            state[1] = 1;
            (*gObjectTriggerInterface)->runSequence(*(u8*)(placement + 0x22), obj,
                                                    0xffffffff);
        }
        else
        {
            *(u8*)(*(int*)(state + 4) + 0xaf) |= 0x20;
            *(u8*)((int)obj + 0xaf) &= ~8;
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
                         ((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ);
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
