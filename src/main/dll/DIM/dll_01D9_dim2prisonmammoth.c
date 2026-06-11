#include "main/dll/baddie_state.h"
#include "main/objHitReact.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct Dim2prisonmammothPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 unk19;
    u8 pad1A[0x20 - 0x1A];
} Dim2prisonmammothPlacement;


typedef struct Dim2prisonmammothState
{
    s32 unk0;
    u8 pad4[0x25F - 0x4];
    u8 unk25F;
    u8 pad260[0x274 - 0x260];
    s16 unk274;
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
    u8 unk5FC;
    u8 pad5FD[0x604 - 0x5FD];
} Dim2prisonmammothState;


/* DLL 0x76 (DIMSnowHorn1 / dim2prisonmammoth) fragment: head/vtable live in placeholder_802BACC0 + placeholder_802BB4B0; consolidate when those adjacent units are graduated. */

typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} ByteFlags;

extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPositionArray();
extern undefined4 ObjPath_GetPointLocalPosition();
extern undefined4 ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objAnimFn_80038f38();
extern undefined4 dll_2E_func03();
extern uint countLeadingZeros();

extern f64 DOUBLE_803e8f08;
extern f64 DOUBLE_803e8f78;
extern f64 DOUBLE_803e9098;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dd3d4;
extern f32 FLOAT_803dd3f4;
extern f32 FLOAT_803dd3f8;
extern f32 FLOAT_803e8ecc;
extern f32 FLOAT_803e8ed8;
extern f32 FLOAT_803e8ef0;
extern f32 FLOAT_803e8f3c;
extern f32 FLOAT_803e8f40;
extern f32 FLOAT_803e8f44;
extern f32 FLOAT_803e8f48;
extern f32 FLOAT_803e8f4c;
extern f32 FLOAT_803e8f50;
extern f32 FLOAT_803e8f58;
extern f32 FLOAT_803e8f5c;
extern f32 FLOAT_803e8f60;
extern f32 FLOAT_803e8f64;
extern f32 FLOAT_803e8f80;
extern f32 FLOAT_803e8f84;
extern f32 FLOAT_803e8f88;
extern f32 FLOAT_803e8f8c;
extern f32 FLOAT_803e8f90;
extern f32 FLOAT_803e8f94;
extern f32 FLOAT_803e8f98;
extern f32 FLOAT_803e8f9c;
extern f32 FLOAT_803e8fa0;
extern f32 FLOAT_803e8fa4;
extern f32 FLOAT_803e8fa8;
extern f32 FLOAT_803e8fac;
extern f32 FLOAT_803e8fb0;
extern f32 FLOAT_803e8fb4;
extern f32 FLOAT_803e8fb8;
extern f32 FLOAT_803e8fbc;
extern f32 FLOAT_803e8fc0;
extern f32 FLOAT_803e8fc4;
extern f32 FLOAT_803e8fc8;
extern f32 FLOAT_803e8fcc;
extern f32 FLOAT_803e8fd0;
extern f32 FLOAT_803e8fd4;
extern f32 FLOAT_803e8fd8;
extern f32 FLOAT_803e8fdc;
extern f32 FLOAT_803e8fe0;
extern f32 FLOAT_803e8fe4;
extern f32 FLOAT_803e8fe8;
extern f32 FLOAT_803e8fec;
extern f32 FLOAT_803e8ff0;
extern f32 FLOAT_803e8ff4;
extern f32 FLOAT_803e9004;
extern f32 FLOAT_803e9008;
extern f32 FLOAT_803e9010;
extern f32 FLOAT_803e9014;
extern f32 FLOAT_803e9018;
extern f32 FLOAT_803e901c;
extern f32 FLOAT_803e9020;
extern f32 FLOAT_803e9024;
extern f32 FLOAT_803e9028;
extern f32 FLOAT_803e902c;
extern f32 FLOAT_803e903c;
extern f32 FLOAT_803e9040;
extern f32 FLOAT_803e9044;
extern f32 FLOAT_803e9048;
extern f32 FLOAT_803e904c;
extern f32 FLOAT_803e9050;
extern f32 FLOAT_803e9054;
extern f32 FLOAT_803e9058;
extern f32 FLOAT_803e905c;
extern f32 FLOAT_803e9060;
extern f32 FLOAT_803e9064;
extern f32 FLOAT_803e9068;
extern f32 FLOAT_803e906c;
extern f32 FLOAT_803e9070;
extern f32 FLOAT_803e9074;
extern f32 FLOAT_803e9078;
extern f32 FLOAT_803e907c;
extern f32 FLOAT_803e9080;
extern f32 FLOAT_803e9084;
extern f32 FLOAT_803e9088;
extern f32 FLOAT_803e908c;
extern f32 FLOAT_803e9090;
extern f32 FLOAT_803e9094;
extern f32 FLOAT_803e90a0;
extern f32 FLOAT_803e90a4;
extern f32 FLOAT_803e90a8;
extern f32 FLOAT_803e90ac;
extern f32 FLOAT_803e90b0;
extern f32 FLOAT_803e90b4;
extern f32 FLOAT_803e90b8;
extern f32 FLOAT_803e90bc;

/*
 * --INFO--
 *
 * Function: DIMSnowHorn1_update
 * EN v1.0 Address: 0x802BB720
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BBC14
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    f32 f0;
    f32 f4;
    f32 f8;
    s16 hc;
    u8 pad_e[2];
    f32 f10;
    f32 f14;
    f32 f18;
    s16 h1c;
    u16 h1e;
    u16 h20;
    u8 pad_22[2];
} SnowHornEntry;

typedef struct
{
    u8 pad[0x94];
    u8 flag;
} SnowHornFlags;

extern void* Obj_GetPlayerObject(void);
extern u8 lbl_80335030[];
extern void fn_8003A168(int obj, int q);
extern void characterDoEyeAnims(int obj, int q);
extern void fn_8003B500(int obj, int q, f32 f);
extern void fn_802BB4B4(int obj, int a, int slot);
extern void buttonDisable(int a, int b);
extern void setAButtonIcon(int icon);
extern int getCurMapLayer(void);
extern int GameBit_Set(int bit, int val);
extern f32 Vec_distance(int a, int b);
extern f32 getXZDistance(int a, int b);
extern char* ObjGroup_FindNearestObject(int group, int obj, f32* distInOut);
extern void setMatrixFromObjectPos(f32* out, void* vec);
extern void Matrix_TransformPoint(f32* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern int* gNewCloudsInterface;
extern u8 framesThisStep;
extern f32 lbl_803E8234;
extern f32 lbl_803E8240;
extern f32 lbl_803E8258;
extern f32 lbl_803E82AC;
extern f32 lbl_803E82B0;
extern f32 lbl_803E82B4;

extern int GameBit_Get(int id);
extern f32 lbl_803E82D0;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern f32 lbl_803E83E8;
extern f32 lbl_803E83A4;
extern void fn_8003B950(int mtx);

extern void playerTailFn_80026b3c(int* p1, int p2, int p3, void* p4);
extern void* lbl_803DE4D0;

extern int gDRCloudRunnerStateHandlers[];
extern void* gDRCloudRunnerDefaultStateHandler;
extern int DR_CloudRunner_stateHandler00(int obj);
extern int DR_CloudRunner_stateHandler01(int obj, int p2);
extern int DR_CloudRunner_stateHandler02(int obj, int p2);
extern int DR_CloudRunner_stateHandler03(int obj, int p2);
extern int DR_CloudRunner_stateHandler04(int obj, int p2);
extern void DR_CloudRunner_stateHandler05();
extern void DR_CloudRunner_stateHandler06();

extern int gDim2PrisonMammothStateHandlers[];
extern int gDREarthWarriorStateHandlers[];
extern void* gDim2PrisonMammothDefaultStateHandler;
extern void* gDREarthWarriorDefaultStateHandler;
extern int dim2prisonmammoth_stateHandler01(int obj, int p2);
extern int dim2prisonmammoth_stateHandler02(int obj, int p2);
extern int dim2prisonmammoth_stateHandler03(int obj, int p2);
extern void DR_EarthWarrior_stateHandler01();
extern void DR_EarthWarrior_stateHandler02();
extern int DR_EarthWarrior_stateHandler03(int obj, int p2);

extern f32 lbl_803E82C0;
extern f32 lbl_803E82C4;
extern f32 lbl_803E82C8;
extern f32 lbl_803E82CC;
extern f32 lbl_803DC758;
extern s16 lbl_803DC754;
extern int randomGetRange(int lo, int hi);
extern int RandomTimer_UpdateRangeTrigger(int p, f32 a, f32 b);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern void Sfx_PlayFromObject(int obj, int id);

extern f32 lbl_803E83F4;
extern f32 lbl_803E83F8;
extern f32 lbl_803E83BC;
extern f32 lbl_803E8408;
extern f32 lbl_803E840C;
extern s16 lbl_803DC79A;
extern void fn_802BF0C8(int obj, int p2, int mode);
extern f32 lbl_803E8304;
extern f32 GX_F32_256;
extern f32 lbl_803DC76C;
extern f32 lbl_803E8338;
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 m);
extern void playerAddHealth(int obj, int amt);

extern void dll_2E_func06();
extern f32 lbl_803E83A8;
extern f32 lbl_803E8360;
extern f32 lbl_803E8354;
extern f32 lbl_803E8364;

extern void fn_80026C88(int p);
extern int Obj_FreeObject(int obj);

extern int objAudioFn_800393f8(int obj, void* audio, int soundId, int volume, int p5, int p6);
extern void textureFree(int handle);
extern f32 lbl_803E82E8;
extern int lbl_8033527C[];
extern void* gDIMSnowHorn1Texture;


extern f32 lbl_803E8410;

extern int* gPlayerInterface;
int fn_802BC3F0(int obj, int p2, ObjAnimUpdateState* animUpdate);


extern f32 lbl_803DC78C;
extern f32 lbl_803DC790;

extern void mtx44_mult(void* lhs, void* rhs, void* out);
extern f32 lbl_803DB170[];

extern void DIMSnowHorn1_stateHandler00();
extern void DIMSnowHorn1_stateHandler01();
extern void DIMSnowHorn1_stateHandler02();
extern void DIMSnowHorn1_stateHandler03();
extern void DIMSnowHorn1_stateHandler04();
extern void DIMSnowHorn1_stateHandler05();
extern void DIMSnowHorn1_stateHandler06();
extern void DIMSnowHorn1_stateHandler07();
extern void DIMSnowHorn1_stateHandler08();
extern void DIMSnowHorn1_stateHandler09();
extern void DIMSnowHorn1_stateHandler0A();
extern void DIMSnowHorn1_stateHandler0B();
extern void DIMSnowHorn1_defaultStateHandler();
extern int gDIMSnowHorn1StateHandlers[];
extern void* gDIMSnowHorn1DefaultStateHandler;
extern s16 gDIMSnowHorn1TextureId;
extern int textureLoad(int id, int p2);

extern int DIMSnowHorn1_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate);
extern int lbl_803E8230;
extern int lbl_803DC734;
extern f32 lbl_803E82B8;
extern void dll_2E_func05(int obj, int q, int a, int b, int c);

extern int dll_2E_func07(int obj, int p3, void* q, int a, int b);

extern int dll_2E_func0A(int a, void* out);
extern void dll_2E_func08(int q, int a, int b);
extern f32 lbl_803E8414;
extern f32 lbl_803E8424;
void fn_802BF0C8(int obj, int inner, int bit);

extern u8 lbl_803DC750;
extern ObjHitReactEntry lbl_803351A8[];
extern f32 timeDelta;
extern void saveGame_saveObjectPos(int obj);

extern u8 lbl_803356F0[];
extern int lbl_803E83A0;
extern int lbl_803DC770;
extern int lbl_803DC774;
extern int lbl_803DC778;
extern int lbl_803DC77C;
extern int lbl_803DC780;
extern int lbl_803DC784;

extern void* Camera_GetCurrentViewSlot(void);
extern int padGetStickX(int p);
extern int padGetStickY(int p);
extern int getButtonsJustPressed(int p);
extern int getButtonsHeld(int p);
extern int Obj_UpdateRomCurveFollowVelocity(int obj, int q, f32 a, f32 b, f32 c, int d);
extern int lbl_803DE4D8;
extern f32 lbl_803E83B4;
void fn_802BF4D8(int obj);

extern void fn_802B0EA4(int obj, int q, int inner);
extern void fn_802B1BF8(int obj, int q, int inner, f32 t);
extern void fn_802B1B28(int obj, f32 t);

extern void fn_80137948(const char* fmt, ...);
extern char sOnCloudFormat[];
extern f32 lbl_803E8418;
extern f32 lbl_803E841C;
extern f32 lbl_803E8420;

extern u8 Obj_IsLoadingLocked(int obj);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int s, int b, int c, int d, int e);
extern void vecRotateZXY(void* a, void* b);
extern void voxmaps_worldToGrid(void* src, void* grid);
extern int voxmaps_traceLine(void* a, void* b, void* c, int d, int e);
extern void voxmaps_gridToWorld(void* grid, void* out);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E83AC;
extern f32 lbl_803E83B0;

extern f32 lbl_803E82EC;
extern f32 GXInit_ClearColor;
extern f32 GXInit_BlackColor;
extern f32 GXInit_WhiteColor;
extern f32 lbl_803E82FC;
extern f32 lbl_803E8300;
extern f32 lbl_803E8308;
extern f32 lbl_803E830C;

extern int getAngle(f32 deltaX, f32 deltaZ);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern f32 lbl_803E83FC;

/* Pattern wrappers. */
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

#pragma peephole off
int dim2prisonmammoth_stateHandler00(int* obj)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    switch ((s8)((Dim2prisonmammothPlacement*)sub)->unk19)
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

#pragma peephole on
void dim2prisonmammoth_release(void)
{
}

#pragma scheduling off
void fn_802BC788(int a, int b)
{
    playerTailFn_80026b3c((int*)b, *(int*)b, *(int*)(*(int*)((char*)a + 0xb8) + 0x14f8), 0);
}

void dim2prisonmammoth_initialise(void)
{
    ((void**)gDim2PrisonMammothStateHandlers)[0] = (void*)dim2prisonmammoth_stateHandler00;
    ((void**)gDim2PrisonMammothStateHandlers)[1] = (void*)dim2prisonmammoth_stateHandler01;
    ((void**)gDim2PrisonMammothStateHandlers)[2] = (void*)dim2prisonmammoth_stateHandler02;
    ((void**)gDim2PrisonMammothStateHandlers)[3] = (void*)dim2prisonmammoth_stateHandler03;
    gDim2PrisonMammothDefaultStateHandler = (void*)dim2prisonmammoth_defaultStateHandler;
}

#pragma peephole off
int dim2prisonmammoth_stateHandler03(int obj, int p2)
{
    f32 fz = lbl_803E82C0;
    ((BaddieState*)p2)->animSpeedC = fz;
    ((BaddieState*)p2)->animSpeedB = fz;
    ((BaddieState*)p2)->animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)p2 + 0) |= 0x200000;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        int k = randomGetRange(0, 1);
        ((BaddieState*)p2)->moveSpeed = (&lbl_803DC758)[k];
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC754)[k], lbl_803E82C0, 0);
    }
    if (*(s8*)&((BaddieState*)p2)->moveDone != 0)
    {
        return -1;
    }
    return 0;
}

int dim2prisonmammoth_stateHandler02(int obj, int p2)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 fz = lbl_803E82C0;
    ((BaddieState*)p2)->animSpeedC = fz;
    ((BaddieState*)p2)->animSpeedB = fz;
    ((BaddieState*)p2)->animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)p2 + 0) |= 0x200000;
    ((BaddieState*)p2)->moveSpeed = lbl_803E82C4;
    if (((GameObject*)obj)->anim.currentMove != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, fz, 0);
    }
    ((Dim2prisonmammothState*)inner)->unk38C = randomGetRange(0x4b0, 0x960);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        buttonDisable(0, 0x100);
    }
    return 0;
}

int dim2prisonmammoth_stateHandler01(int obj, int p2)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 fz = lbl_803E82C0;
    ((BaddieState*)p2)->animSpeedC = fz;
    ((BaddieState*)p2)->animSpeedB = fz;
    ((BaddieState*)p2)->animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)p2 + 0) |= 0x200000;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ((BaddieState*)p2)->moveSpeed = lbl_803E82C4;
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            ObjAnim_SetCurrentMove(obj, 5, fz, 0);
        }
        ((Dim2prisonmammothState*)inner)->unk38C = randomGetRange(0x4b0, 0x960);
    }
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
    {
        GameBit_Set(0x223, 1);
        buttonDisable(0, 0x100);
    }
    if (RandomTimer_UpdateRangeTrigger(inner + 0x600, lbl_803E82C8, lbl_803E82CC))
    {
        Sfx_PlayFromObject(obj, 0x43a);
    }
    return 0;
}

void dim2prisonmammoth_init(int obj, int p2)
{
    int inner;
    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)p2 + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)fn_802BC3F0;
    inner = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0xa10;
        ((GameObject*)obj)->anim.modelState->flags |= 0x8020;
    }
    (*(void (*)(int, int, int, int))(*(int*)(*gPlayerInterface + 0x4)))(obj, inner, 4, 1);
    ((Dim2prisonmammothState*)inner)->unk25F = 0;
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

int fn_802BC3F0(int obj, int p2, ObjAnimUpdateState* animUpdate)
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

    Matrix_TransformPoint(matrix, lbl_803E82C0, lbl_803E82C0, lbl_803E82C0,
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
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
    if (((&lbl_803DC750)[((Dim2prisonmammothState*)inner)->unk274] & 8) == 0)
    {
        ((Dim2prisonmammothState*)inner)->unk5FC = ((u8 (*)(int, ObjHitReactEntry*, u32, u32, f32*))ObjHitReact_Update)(
            obj, lbl_803351A8, 1, ((Dim2prisonmammothState*)inner)->unk5FC, (f32*)(inner + 0x390));
        if (((Dim2prisonmammothState*)inner)->unk5FC != 0)
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
    Matrix_TransformPoint(matrix, lbl_803E82C0, lbl_803E82C0, lbl_803E82C0,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosX,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosY,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosZ);
    ((Dim2prisonmammothState*)inner)->unk354 = 0;
    ((Dim2prisonmammothState*)inner)->unk0 &= ~0x8000;
    ((Dim2prisonmammothState*)inner)->unk290 = lbl_803E82C0;
    ((Dim2prisonmammothState*)inner)->unk28C = lbl_803E82C0;
    ((Dim2prisonmammothState*)inner)->unk31C = 0;
    ((Dim2prisonmammothState*)inner)->unk318 = 0;
    ((Dim2prisonmammothState*)inner)->unk330 = 0;
    ((Dim2prisonmammothState*)inner)->unk0 |= 0x400000;
    (*(void (*)(int, int, f32, f32, int, void*))(*(int*)(*gPlayerInterface + 0x8)))(
        obj, inner, timeDelta, timeDelta, (int)gDim2PrisonMammothStateHandlers, &gDim2PrisonMammothDefaultStateHandler);
    saveGame_saveObjectPos(obj);
}
