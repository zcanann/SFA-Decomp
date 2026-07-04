/* DLL 0x1D9 - DIM2 Prison Mammoth: mammoth baddie state machine for the
 * DIM2 prison area.  Handles idle/stomp/charge state transitions, eye
 * animations, hit-react, and the tail-whip player interaction. */
#include "main/dll/baddie_state.h"
#include "main/gamebits.h"
#include "main/objHitReact.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "main/gameplay_runtime.h"
#include "main/audio/sfx_trigger_ids.h"

#define DIM2PRISONMAMMOTH_OBJFLAG_HITDETECT_DISABLED 0x2000
#define PAD_BUTTON_A 0x100

typedef struct Dim2prisonmammothPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 rotByte; /* 0x18 packed into rotX as (s16)(rotByte << 8) at init */
    s8 spawnVariant; /* 0x19 spawn variant selector (stateHandler00) */
    u8 pad1A[0x20 - 0x1A];
} Dim2prisonmammothPlacement;

typedef struct Dim2prisonmammothState
{
    s32 flags; /* 0x0 object flag bits (0x8000, 0x400000) */
    u8 pad4[0x25F - 0x4];
    u8 unk25F;
    u8 pad260[0x274 - 0x260];
    s16 stateIndex; /* 0x274 indexes gPrisonMammothStateFlagsTable */
    u8 pad276[0x28C - 0x276];
    f32 unk28C;
    f32 unk290;
    u8 pad294[0x318 - 0x294];
    s32 unk318;
    s32 unk31C;
    u8 pad320[0x330 - 0x320];
    s16 unk330;
    u8 pad332[0x354 - 0x332];
    u8 unk354;
    u8 pad355[0x38C - 0x355];
    s16 unk38C;
    u8 pad38E[0x5FC - 0x38E];
    u8 hitReactState; /* 0x5FC carried in/out of ObjHitReact_Update */
    u8 pad5FD[0x604 - 0x5FD];
} Dim2prisonmammothState;

extern void fn_8003A168(int p1, int p2);
extern void characterDoEyeAnims(int obj, int p2);
extern void buttonDisable(int port, u32 mask);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 lbl_803E82D0;
extern void playerTailFn_80026b3c(int* p1, int p2, int p3, void* p4);
extern int gDim2PrisonMammothStateHandlers[];
extern void* gDim2PrisonMammothDefaultStateHandler;
extern int dim2prisonmammoth_stateHandler01(int obj, int p2);
extern int dim2prisonmammoth_stateHandler02(int obj, int p2);
extern int dim2prisonmammoth_stateHandler03(int obj, int p2);
extern f32 lbl_803E82C0;
extern f32 gPrisonMammothMoveSpeed;
extern f32 lbl_803E82C8;
extern f32 lbl_803E82CC;
extern f32 gPrisonMammothMoveSpeedTable;
extern s16 gPrisonMammothMoveIdTable;
extern int *gPlayerInterface;
int fn_802BC3F0(int obj, int state, ObjAnimUpdateState *animUpdate);

extern u8 gPrisonMammothStateFlagsTable;
extern ObjHitReactEntry gPrisonMammothHitReactEntry[];
extern f32 timeDelta;
extern void saveGame_saveObjectPos(int obj);

int dim2prisonmammoth_defaultStateHandler(void) { return 0x0; }

int dim2prisonmammoth_getExtraSize(void) { return 0x604; }

int dim2prisonmammoth_getObjectTypeId(void) { return 0; }

void dim2prisonmammoth_free(void)
{
}

void dim2prisonmammoth_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E82D0);
    }
}

void dim2prisonmammoth_hitDetect(void)
{
}

int dim2prisonmammoth_stateHandler00(int* obj)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    switch ((s8)((Dim2prisonmammothPlacement*)sub)->spawnVariant)
    {
    case 0:
        if ((u32)GameBit_Get(548) != 0) return 3;
        return 2;
    case 1:
        if ((u32)GameBit_Get(707) != 0) return 3;
        return 3;
    default:
        return 0;
    }
}

void dim2prisonmammoth_release(void)
{
}

void fn_802BC788(int a, int b)
{
    playerTailFn_80026b3c((int*)b, *(int*)b, *(int*)(*(int*)&((GameObject*)a)->extra + 0x14f8), 0);
}

void dim2prisonmammoth_initialise(void)
{
    ((void**)gDim2PrisonMammothStateHandlers)[0] = dim2prisonmammoth_stateHandler00;
    ((void**)gDim2PrisonMammothStateHandlers)[1] = dim2prisonmammoth_stateHandler01;
    ((void**)gDim2PrisonMammothStateHandlers)[2] = dim2prisonmammoth_stateHandler02;
    ((void**)gDim2PrisonMammothStateHandlers)[3] = dim2prisonmammoth_stateHandler03;
    gDim2PrisonMammothDefaultStateHandler = dim2prisonmammoth_defaultStateHandler;
}

int dim2prisonmammoth_stateHandler03(int obj, int state)
{
    f32 fz = lbl_803E82C0;
    ((BaddieState*)state)->animSpeedC = fz;
    ((BaddieState*)state)->animSpeedB = fz;
    ((BaddieState*)state)->animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    if (*(s8*)&((BaddieState*)state)->moveJustStartedA != 0)
    {
        int k = randomGetRange(0, 1);
        ((BaddieState*)state)->moveSpeed = (&gPrisonMammothMoveSpeedTable)[k];
        ObjAnim_SetCurrentMove(obj, (&gPrisonMammothMoveIdTable)[k], lbl_803E82C0, 0);
    }
    if (*(s8*)&((BaddieState*)state)->moveDone != 0)
    {
        return -1;
    }
    return 0;
}

int dim2prisonmammoth_stateHandler02(int obj, int state)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 fz = lbl_803E82C0;
    ((BaddieState*)state)->animSpeedC = fz;
    ((BaddieState*)state)->animSpeedB = fz;
    ((BaddieState*)state)->animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    ((BaddieState*)state)->moveSpeed = gPrisonMammothMoveSpeed;
    if (((GameObject*)obj)->anim.currentMove != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, fz, 0);
    }
    ((Dim2prisonmammothState*)inner)->unk38C = randomGetRange(0x4b0, 0x960);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int dim2prisonmammoth_stateHandler01(int obj, int state)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 fz = lbl_803E82C0;
    ((BaddieState*)state)->animSpeedC = fz;
    ((BaddieState*)state)->animSpeedB = fz;
    ((BaddieState*)state)->animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    if (*(s8*)&((BaddieState*)state)->moveJustStartedA != 0)
    {
        ((BaddieState*)state)->moveSpeed = gPrisonMammothMoveSpeed;
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            ObjAnim_SetCurrentMove(obj, 5, fz, 0);
        }
        ((Dim2prisonmammothState*)inner)->unk38C = randomGetRange(0x4b0, 0x960);
    }
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        GameBit_Set(0x223, 1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    if (RandomTimer_UpdateRangeTrigger((void*)(inner + 0x600), lbl_803E82C8, lbl_803E82CC))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_hightop_call1);
    }
    return 0;
}

void dim2prisonmammoth_init(int obj, int params)
{
    int inner;
    ((GameObject*)obj)->anim.rotX = (s16)(((Dim2prisonmammothPlacement*)params)->rotByte << 8);
    ((GameObject*)obj)->animEventCallback = fn_802BC3F0;
    inner = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0xa10;
        ((GameObject*)obj)->anim.modelState->flags |= 0x8020LL;
    }
    (*(void (*)(int, int, int, int))(*(int*)(*gPlayerInterface + 0x4)))(obj, inner, 4, 1);
    ((Dim2prisonmammothState*)inner)->unk25F = 0;
    ((GameObject*)obj)->objectFlags |= DIM2PRISONMAMMOTH_OBJFLAG_HITDETECT_DISABLED;
}

int fn_802BC3F0(int obj, int state, ObjAnimUpdateState* animUpdate)
{
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    int inner;

    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    inner = *(int*)&((GameObject*)obj)->extra;
    (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, inner, 2);

    v.mat[1] = ((GameObject*)obj)->anim.localPosX;
    v.mat[2] = ((GameObject*)obj)->anim.localPosY;
    v.mat[3] = ((GameObject*)obj)->anim.localPosZ;
    v.angles[0] = ((GameObject*)obj)->anim.rotX;
    v.angles[1] = ((GameObject*)obj)->anim.rotY;
    v.angles[2] = ((GameObject*)obj)->anim.rotZ;
    v.mat[0] = ((GameObject*)obj)->anim.rootMotionScale;
    setMatrixFromObjectPos(matrix, v.angles);

    Matrix_TransformPoint(matrix, 0.0f, 0.0f, 0.0f,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosX,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosY,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosZ);
    return 0;
}

void dim2prisonmammoth_update(int obj)
{
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    int inner = *(int*)&((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    if (((&gPrisonMammothStateFlagsTable)[((Dim2prisonmammothState*)inner)->stateIndex] & 8) == 0)
    {
        ((Dim2prisonmammothState*)inner)->hitReactState = ((u8 (*)(int, ObjHitReactEntry*, u32, u32, f32*))ObjHitReact_Update)(
            obj, gPrisonMammothHitReactEntry, 1, ((Dim2prisonmammothState*)inner)->hitReactState, (f32*)(inner + 0x390));
        if (((Dim2prisonmammothState*)inner)->hitReactState != 0)
        {
            fn_8003A168(obj, inner + 0x35c);
            characterDoEyeAnims(obj, inner + 0x35c);
            return;
        }
    }
    characterDoEyeAnims(obj, inner + 0x35c);
    v.mat[1] = ((GameObject*)obj)->anim.localPosX;
    v.mat[2] = ((GameObject*)obj)->anim.localPosY;
    v.mat[3] = ((GameObject*)obj)->anim.localPosZ;
    v.angles[0] = ((GameObject*)obj)->anim.rotX;
    v.angles[1] = ((GameObject*)obj)->anim.rotY;
    v.angles[2] = ((GameObject*)obj)->anim.rotZ;
    v.mat[0] = ((GameObject*)obj)->anim.rootMotionScale;
    setMatrixFromObjectPos(matrix, v.angles);
    Matrix_TransformPoint(matrix, 0.0f, 0.0f, 0.0f,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosX,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosY,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosZ);
    ((Dim2prisonmammothState*)inner)->unk354 = 0;
    ((Dim2prisonmammothState*)inner)->flags &= ~0x8000;
    {
        f32 fz = lbl_803E82C0;
        ((Dim2prisonmammothState*)inner)->unk290 = fz;
        ((Dim2prisonmammothState*)inner)->unk28C = fz;
    }
    ((Dim2prisonmammothState*)inner)->unk31C = 0;
    ((Dim2prisonmammothState*)inner)->unk318 = 0;
    ((Dim2prisonmammothState*)inner)->unk330 = 0;
    ((Dim2prisonmammothState*)inner)->flags |= 0x400000;
    (*(void (*)(int, int, f32, f32, int, void*))(*(int*)(*gPlayerInterface + 0x8)))(
        obj, inner, timeDelta, timeDelta, (int)gDim2PrisonMammothStateHandlers, &gDim2PrisonMammothDefaultStateHandler);
    saveGame_saveObjectPos(obj);
}

ObjHitReactEntry gPrisonMammothHitReactEntry[] = {
    {730, 885, 48, {0xFF, 0xFF}, 0, {0, 0, 0}, 0.012f, {0, 0, 0, 0}},
};
