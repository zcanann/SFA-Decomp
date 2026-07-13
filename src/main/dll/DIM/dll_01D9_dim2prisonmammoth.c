/* DLL 0x1D9 - DIM2 Prison Mammoth: mammoth baddie state machine for the
 * DIM2 prison area.  Handles idle/stomp/charge state transitions, eye
 * animations, hit-react, and the tail-whip player interaction. */
#include "main/dll/baddie_state.h"
#include "main/dll/savegame.h"
#include "main/gamebits.h"
#include "main/objHitReact.h"
#include "main/game_object.h"
#include "main/objprint_character_api.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "main/gameplay_runtime.h"
#include "main/object_descriptor.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/DIM/dll_01D9_dim2prisonmammoth.h"
#include "main/player_control_interface.h"

#define DIM2PRISONMAMMOTH_OBJFLAG_HITDETECT_DISABLED 0x2000
#define PAD_BUTTON_A                                 0x100

extern int gDim2PrisonMammothStateHandlers[];
extern void* gDim2PrisonMammothDefaultStateHandler;
extern f32 gPrisonMammothMoveSpeedTable;
extern s16 gPrisonMammothMoveIdTable;
extern u8 gPrisonMammothStateFlagsTable;
extern ObjHitReactEntry gPrisonMammothHitReactEntry[];

extern void fn_8003A168(GameObject* p1, int p2);
extern void buttonDisable(int port, u32 mask);

int dim2prisonmammoth_defaultStateHandler(void)
{
    return 0x0;
}

int dim2prisonmammoth_stateHandler03(GameObject* obj, int state)
{
    f32 fz = 0.0f;
    ((BaddieState*)state)->animSpeedC = fz;
    ((BaddieState*)state)->animSpeedB = fz;
    ((BaddieState*)state)->animSpeedA = fz;
    (obj)->anim.velocityX = fz;
    (obj)->anim.velocityY = fz;
    (obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    if (*(s8*)&((BaddieState*)state)->moveJustStartedA != 0)
    {
        int k = randomGetRange(0, 1);
        ((BaddieState*)state)->moveSpeed = (&gPrisonMammothMoveSpeedTable)[k];
        ObjAnim_SetCurrentMove((int)obj, (&gPrisonMammothMoveIdTable)[k], 0.0f, 0);
    }
    if (*(s8*)&((BaddieState*)state)->moveDone != 0)
    {
        return -1;
    }
    return 0;
}

int dim2prisonmammoth_stateHandler02(GameObject* obj, int state)
{
    int inner = *(int*)&(obj)->extra;
    f32 fz = 0.0f;
    ((BaddieState*)state)->animSpeedC = fz;
    ((BaddieState*)state)->animSpeedB = fz;
    ((BaddieState*)state)->animSpeedA = fz;
    (obj)->anim.velocityX = fz;
    (obj)->anim.velocityY = fz;
    (obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    ((BaddieState*)state)->moveSpeed = 0.005f;
    if ((obj)->anim.currentMove != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, fz, 0);
    }
    ((Dim2prisonmammothState*)inner)->unk38C = randomGetRange(0x4b0, 0x960);
    *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    if (*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int dim2prisonmammoth_stateHandler01(GameObject* obj, int state)
{
    int inner = *(int*)&(obj)->extra;
    f32 fz = 0.0f;
    ((BaddieState*)state)->animSpeedC = fz;
    ((BaddieState*)state)->animSpeedB = fz;
    ((BaddieState*)state)->animSpeedA = fz;
    (obj)->anim.velocityX = fz;
    (obj)->anim.velocityY = fz;
    (obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    if (*(s8*)&((BaddieState*)state)->moveJustStartedA != 0)
    {
        ((BaddieState*)state)->moveSpeed = 0.005f;
        if ((obj)->anim.currentMove != 5)
        {
            ObjAnim_SetCurrentMove((int)obj, 5, fz, 0);
        }
        ((Dim2prisonmammothState*)inner)->unk38C = randomGetRange(0x4b0, 0x960);
    }
    if (*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        mainSetBits(GAMEBIT_DIM_FoundBelinaTe, 1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    if (RandomTimer_UpdateRangeTrigger((void*)(inner + 0x600), 4.0f, 8.0f))
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_hightop_call1);
    }
    return 0;
}

int dim2prisonmammoth_stateHandler00(int* obj)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    switch ((s8)((Dim2prisonmammothPlacement*)sub)->spawnVariant)
    {
    case 0:
        if ((u32)mainGetBit(548) != 0)
            return 3;
        return 2;
    case 1:
        if ((u32)mainGetBit(GAMEBIT_DIM_ReachedBottom) != 0)
            return 3;
        return 3;
    default:
        return 0;
    }
}

int dim2prisonmammoth_SeqFn(int obj, int state, ObjAnimUpdateState* animUpdate)
{
    MatrixTransform v;
    f32 matrix[16];
    int inner;

    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    inner = *(int*)&((GameObject*)obj)->extra;
    (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, inner, 2);

    v.x = ((GameObject*)obj)->anim.localPosX;
    v.y = ((GameObject*)obj)->anim.localPosY;
    v.z = ((GameObject*)obj)->anim.localPosZ;
    v.rotX = ((GameObject*)obj)->anim.rotX;
    v.rotY = ((GameObject*)obj)->anim.rotY;
    v.rotZ = ((GameObject*)obj)->anim.rotZ;
    v.scale = ((GameObject*)obj)->anim.rootMotionScale;
    setMatrixFromObjectPos(matrix, &v);

    Matrix_TransformPoint(matrix, 0.0f, 0.0f, 0.0f, &((GameObject*)obj)->anim.modelState->overrideWorldPosX,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosY,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosZ);
    return 0;
}

int dim2prisonmammoth_getExtraSize(void)
{
    return 0x604;
}

int dim2prisonmammoth_getObjectTypeId(void)
{
    return 0;
}

void dim2prisonmammoth_free(void)
{
}

void dim2prisonmammoth_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, 1.0f);
    }
}

void dim2prisonmammoth_hitDetect(void)
{
}

void dim2prisonmammoth_update(int obj)
{
    MatrixTransform v;
    f32 matrix[16];
    int inner = *(int*)&((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    if (((&gPrisonMammothStateFlagsTable)[((Dim2prisonmammothState*)inner)->stateIndex] & 8) == 0)
    {
        ((Dim2prisonmammothState*)inner)->hitReactState =
            ((u8 (*)(int, ObjHitReactEntry*, u32, u32, f32*))ObjHitReact_Update)(
                obj, gPrisonMammothHitReactEntry, 1, ((Dim2prisonmammothState*)inner)->hitReactState,
                (f32*)(inner + 0x390));
        if (((Dim2prisonmammothState*)inner)->hitReactState != 0)
        {
            fn_8003A168((GameObject*)(obj), inner + 0x35c);
            characterDoEyeAnimsState((GameObject*)obj, inner + 0x35c);
            return;
        }
    }
    characterDoEyeAnimsState((GameObject*)obj, inner + 0x35c);
    v.x = ((GameObject*)obj)->anim.localPosX;
    v.y = ((GameObject*)obj)->anim.localPosY;
    v.z = ((GameObject*)obj)->anim.localPosZ;
    v.rotX = ((GameObject*)obj)->anim.rotX;
    v.rotY = ((GameObject*)obj)->anim.rotY;
    v.rotZ = ((GameObject*)obj)->anim.rotZ;
    v.scale = ((GameObject*)obj)->anim.rootMotionScale;
    setMatrixFromObjectPos(matrix, &v);
    Matrix_TransformPoint(matrix, 0.0f, 0.0f, 0.0f, &((GameObject*)obj)->anim.modelState->overrideWorldPosX,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosY,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosZ);
    ((Dim2prisonmammothState*)inner)->unk354 = 0;
    ((Dim2prisonmammothState*)inner)->flags &= ~0x8000;
    {
        f32 fz = 0.0f;
        ((Dim2prisonmammothState*)inner)->unk290 = fz;
        ((Dim2prisonmammothState*)inner)->unk28C = fz;
    }
    ((Dim2prisonmammothState*)inner)->unk31C = 0;
    ((Dim2prisonmammothState*)inner)->unk318 = 0;
    ((Dim2prisonmammothState*)inner)->unk330 = 0;
    ((Dim2prisonmammothState*)inner)->flags |= 0x400000;
    (*(void (*)(int, int, f32, f32, int, void*))(*(int*)((char*)*gPlayerInterface + 0x8)))(
        obj, inner, timeDelta, timeDelta, (int)gDim2PrisonMammothStateHandlers, &gDim2PrisonMammothDefaultStateHandler);
    saveGame_saveObjectPos((GameObject*)obj);
}

void dim2prisonmammoth_init(int obj, int params)
{
    int inner;
    ((GameObject*)obj)->anim.rotX = (s16)(((Dim2prisonmammothPlacement*)params)->rotByte << 8);
    ((GameObject*)obj)->animEventCallback = dim2prisonmammoth_SeqFn;
    inner = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0xa10;
        ((GameObject*)obj)->anim.modelState->flags |= 0x8020LL;
    }
    (*(void (*)(int, int, int, int))(*(int*)((char*)*gPlayerInterface + 0x4)))(obj, inner, 4, 1);
    ((Dim2prisonmammothState*)inner)->unk25F = 0;
    ((GameObject*)obj)->objectFlags |= DIM2PRISONMAMMOTH_OBJFLAG_HITDETECT_DISABLED;
}

void dim2prisonmammoth_release(void)
{
}

void dim2prisonmammoth_initialise(void)
{
    ((void**)gDim2PrisonMammothStateHandlers)[0] = dim2prisonmammoth_stateHandler00;
    ((void**)gDim2PrisonMammothStateHandlers)[1] = dim2prisonmammoth_stateHandler01;
    ((void**)gDim2PrisonMammothStateHandlers)[2] = dim2prisonmammoth_stateHandler02;
    ((void**)gDim2PrisonMammothStateHandlers)[3] = dim2prisonmammoth_stateHandler03;
    gDim2PrisonMammothDefaultStateHandler = dim2prisonmammoth_defaultStateHandler;
}

void fn_802BC788(GameObject* obj, int b)
{
    playerTailFn_80026b3c((int*)b, *(int*)b, *(int*)(*(int*)&obj->extra + 0x14f8), 0);
}

ObjHitReactEntry gPrisonMammothHitReactEntry[] = {
    {730, 885, 48, {0xFF, 0xFF}, 0, {0, 0, 0}, 0.012f, {0, 0, 0, 0}},
};

ObjectDescriptor10WithPadding gDIM2PrisonMammothObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)dim2prisonmammoth_initialise,
        (ObjectDescriptorCallback)dim2prisonmammoth_release,
        0,
        (ObjectDescriptorCallback)dim2prisonmammoth_init,
        (ObjectDescriptorCallback)dim2prisonmammoth_update,
        (ObjectDescriptorCallback)dim2prisonmammoth_hitDetect,
        (ObjectDescriptorCallback)dim2prisonmammoth_render,
        (ObjectDescriptorCallback)dim2prisonmammoth_free,
        (ObjectDescriptorCallback)dim2prisonmammoth_getObjectTypeId,
        dim2prisonmammoth_getExtraSize,
    },
    0,
};
