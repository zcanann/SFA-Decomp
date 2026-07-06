/* DLL 0x255 - SnowBike [801EC7A0-801ECEC4) */
#include "main/dll/path_control_interface.h"
#include "main/checkpoint_interface.h"
#include "main/game_ui_interface.h"
#include "main/dll/BW/BWalphaanim.h"
#include "main/dll/dll_0015_curves.h"
#include "main/gamebits.h"
#include "main/vecmath.h"
#include "main/dll/DR/DRpickup.h"
#include "main/mm.h"
#include "main/pad.h"
#include "main/audio/sfx_trigger_ids.h"

#define SNOWBIKE_OBJGROUP 0xa

typedef struct SnowBikeMountState
{
    s16 savedRotX;
    u8 pad2[0xC - 0x2];
    f32 savedPosX;
    f32 savedPosY;
    f32 savedPosZ;
    u8 pad18[0x3D3 - 0x18];
    s8 unk3D3;
    u8 pad3D4[0x3E8 - 0x3D4];
    f32 modelMtxPosX;
    f32 modelMtxPosY;
    f32 modelMtxPosZ;
    u8 pad3F4[0x400 - 0x3F4];
    f32 mountPosX;
    f32 mountPosY;
    f32 mountPosZ;
    u8 pad40C[0x414 - 0x40C];
    f32 unk414;
    u8 pad418[0x420 - 0x418];
    u8 unk420;
    u8 pad421[0x428 - 0x421];
    u8 flags;
    u8 pad429[0x434 - 0x429];
    u8 romListGroupIndex;
    u8 romListItemIndex;
    u8 pad436[0x494 - 0x436];
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
} SnowBikeMountState;

typedef struct SnowBikeSetTypeState
{
    s16 savedRotX;
    u8 pad2[0xC - 0x2];
    f32 savedPosX;
    f32 savedPosY;
    f32 savedPosZ;
    u8 pad18[0x3D3 - 0x18];
    s8 unk3D3;
    u8 pad3D4[0x3E8 - 0x3D4];
    f32 modelMtxPosX;
    f32 modelMtxPosY;
    f32 modelMtxPosZ;
    u8 pad3F4[0x400 - 0x3F4];
    f32 mountPosX;
    f32 mountPosY;
    f32 mountPosZ;
    u8 pad40C[0x414 - 0x40C];
    f32 unk414;
    u8 pad418[0x420 - 0x418];
    u8 unk420;
    s8 bikeType;
    u8 pad422[0x428 - 0x422];
    u8 flags;
    u8 pad429[0x434 - 0x429];
    u8 romListGroupIndex;
    u8 romListItemIndex;
    u8 pad436[0x448 - 0x436];
    s16 completionGameBit;
    u8 pad44A[0x494 - 0x44A];
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    u8 pad4A0[0x4B8 - 0x4A0];
    f32 airMeterMax;       /* 0x4B8 */
    f32 airMeterCurrent;   /* 0x4BC */
    f32 airDrainRate;      /* 0x4C0 */
    u8 pad4C4[0x4C8 - 0x4C4];
} SnowBikeSetTypeState;

extern void ObjGroup_RemoveObject(u32 obj, int group);
extern int lbl_803DC0BC;
extern f32 sqrtf(f32 x);
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5BB0;
extern f32 lbl_803E5BB8;
extern f32 lbl_803E5BA8;
extern f32 lbl_803E5BE4;
extern f32 lbl_803E5BF4;
extern f32 lbl_803E5BFC;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C10;
extern f32 lbl_803E5C14;
extern f32 lbl_803E5C34;
extern f32 lbl_803E5C38;
extern f32 lbl_803E5C3C;
extern f32 lbl_803E5C40;
extern f32 lbl_803E5C44;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5B70;
extern f32 lbl_803E5B90;
extern f32 lbl_803E5B94;
extern f32 lbl_803E5B98;
extern void* mapRomListFindItem(int a, int b, int c, int d, int e);
extern int gSnowBikeMountRomListTable[];
extern void objRenderModelAndHitVolumes(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale);
extern void fn_801E991C(void* obj, void* path);
extern void ObjPath_GetPointWorldPosition(void* obj, int idx, void* out0, void* out1, void* out2, int flag);
extern void fn_801EB940(int obj, u8* state);
extern f32 PSVECMag(f32 * v);
extern void doRumble(f32 duration);
extern int arrayIndexOf(s16* arr, int n, int value);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int ch);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void Sfx_SetObjectSfxVolume(int obj, int sfx, u8 vol, f32 v);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern void OSReport(const char* msg, ...);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern s16 gSnowBikeHitObjectIdTable[];
extern char sSnowBikeVelDebugFmt;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E5B28;
extern f32 lbl_803E5B88;
extern f32 lbl_803E5BA4;
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5C4C;
extern u32 fn_801EAE4C();
extern u32 fn_801EB0D4();
extern u32 fn_801EB634();
extern void textureFree(u32);
extern u32 textureLoadAsset(int);
extern u32 lbl_803DDC60;
extern char lbl_803284E0[];
extern u32 lbl_803E5AE0;
extern void* memcpy(void* dst, const void* src, int n);
extern void Obj_ClearModelSlotIndex(int obj);
extern void SnowBike_animEventCallback();
extern void ObjGroup_AddObject(u32 obj, int group);
extern f32 lbl_803DC0B8;
extern f32 lbl_803DC0C0;
extern f32 lbl_803DC0C4;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5C50;
extern f32 lbl_803E5C54;
extern f32 lbl_803E5C58;
extern f32 lbl_803E5C5C;
extern f32 lbl_803E5C60;
extern f32 lbl_803E5C64;
extern f32 lbl_803E5C68;
extern void Obj_SetModelSlotIndex(int obj, int slot);
extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern int drshackle_updateAttachedPosition(int obj, u8* state);
extern void fn_801EBD60(int obj, u8* state);
extern void fn_801EA240(int obj, u8* state, f32 speed, int val, u8* p, int n);
extern void objApplyVelocity(int obj);
extern int Rcp_GetMotionBlurEnabled(void);
extern void setMotionBlur(u8 enabled, f32 amount);
extern void PSVECScale(f32* src, f32* dst, f32 scale);
extern void PSVECAdd(f32 * a, f32 * b, f32 * dst);
extern float powfBitEstimate(float x, float y);
extern void setAButtonIcon(int x);
extern void setBButtonIcon(int icon);
extern char padGetStickX(int pad);
extern char padGetStickY(int pad);
extern u32 getButtonsHeld(int port);
extern int getAngle(float y, float x);
extern f32 timeDelta;
extern f32 lbl_803E5B6C;
extern f32 lbl_803E5BA0;
extern f32 gSnowBikeBamToDeg;

void SnowBike_func17(void)
{
}

void SnowBike_func16(void)
{
}

int SnowBike_func0E(void) { return 0x2; }
int SnowBike_render2(void) { return 0x0; }
int SnowBike_getExtraSize(void) { return 0x59c; }
int SnowBike_getObjectTypeId(void) { return 0x3; }

u8 SnowBike_func0B(int* obj) { return ((SnowBikeState*)((GameObject*)obj)->extra)->unk420; }

void SnowBike_mount(int obj, f32* x, f32* y, f32* z)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    ((SnowBikeMountState*)state)->mountPosX = ((GameObject*)obj)->anim.localPosX;
    ((SnowBikeMountState*)state)->mountPosY = ((GameObject*)obj)->anim.localPosY;
    ((SnowBikeMountState*)state)->mountPosZ = ((GameObject*)obj)->anim.localPosZ;
    *x = ((SnowBikeMountState*)state)->mountPosX;
    *y = ((SnowBikeMountState*)state)->mountPosY;
    *z = ((SnowBikeMountState*)state)->mountPosZ;
}

void SnowBike_modelMtxFn(int obj, f32* x, f32* y, f32* z)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    *x = ((SnowBikeMountState*)state)->modelMtxPosX;
    *y = ((SnowBikeMountState*)state)->modelMtxPosY;
    *z = ((SnowBikeMountState*)state)->modelMtxPosZ;
}

void SnowBike_func15(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int* table;
    void* found;
    f32 zero;

    table = (int*)((int)gSnowBikeMountRomListTable + (int)(((SnowBikeMountState*)state)->romListGroupIndex) * 12);
    found = mapRomListFindItem(table[((SnowBikeMountState*)state)->romListItemIndex], 0, 0, 0, 0);
    if (found != NULL)
    {
        if (((SnowBikeMountState*)state)->romListGroupIndex != 0)
        {
            ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)found + 0x8);
            ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)found + 0xc);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)found + 0x10);
            ((GameObject*)obj)->anim.rotX = (s16)((*(u8*)((char*)found + 0x29)) << 8);
        }
        (*gCheckpointInterface)->findRouteForObject((GameObject*)obj,
                                                    (CheckpointRouteState*)(state + 0x28), 0);
        ((SnowBikeMountState*)state)->savedPosX = ((GameObject*)obj)->anim.localPosX;
        ((SnowBikeMountState*)state)->savedPosY = ((GameObject*)obj)->anim.localPosY;
        ((SnowBikeMountState*)state)->savedPosZ = ((GameObject*)obj)->anim.localPosZ;
        ((SnowBikeMountState*)state)->savedRotX = ((GameObject*)obj)->anim.rotX;
        zero = lbl_803E5AE8;
        ((SnowBikeMountState*)state)->velocityX = zero;
        ((SnowBikeMountState*)state)->velocityY = zero;
        ((SnowBikeMountState*)state)->velocityZ = zero;
        (*gPathControlInterface)->attachObject((void*)obj, (void*)(state + 0x178));
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosX = ((GameObject*)obj)->anim.localPosX;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosY = ((GameObject*)obj)->anim.localPosY;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosZ = ((GameObject*)obj)->anim.localPosZ;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosX = ((GameObject*)obj)->anim.worldPosX;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosY = ((GameObject*)obj)->anim.worldPosY;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosZ = ((GameObject*)obj)->anim.worldPosZ;
        ((SnowBikeMountState*)state)->unk3D3 = 1;
    }
}

typedef struct DRcradleSnowBikeFlags
{
    u8 resetLatch : 1; /* 0x80 */
    u8 pathActive : 1; /* 0x40 */
    u8 uiPrompt : 1; /* 0x20 */
    u8 impulseLatch : 1; /* 0x10 */
    u8 flags : 4;
} DRcradleSnowBikeFlags;

void fn_801EC7A0(int obj, int state)
{
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;

    v.mat[1] = lbl_803E5AE8;
    v.mat[2] = lbl_803E5AE8;
    v.mat[3] = lbl_803E5AE8;
    v.mat[0] = lbl_803E5AEC;

    v.angles[0] = ((SnowBikeState*)state)->yaw;
    v.angles[1] = 0;
    v.angles[2] = 0;
    setMatrixFromObjectPos((void*)(state + 0x6c), v.angles);

    v.angles[0] = -((SnowBikeState*)state)->yaw;
    v.angles[1] = 0;
    v.angles[2] = 0;
    mtxRotateByVec3s((void*)(state + 0xac), v.angles);

    v.angles[0] = ((SnowBikeState*)state)->yawCurrent;
    v.angles[1] = 0;
    v.angles[2] = 0;
    setMatrixFromObjectPos((void*)(state + 0xec), v.angles);

    v.angles[0] = -((SnowBikeState*)state)->yawCurrent;
    v.angles[1] = 0;
    v.angles[2] = 0;
    mtxRotateByVec3s((void*)(state + 0x12c), v.angles);
}

#pragma dont_inline on
void fn_801EC870(int obj, register int state)
{
    f32 fz, fa, fb, fc;
    DRcradleSnowBikeFlags* flags;
    ((SnowBikeState*)state)->unk52C = lbl_803E5C34;
    ((SnowBikeState*)state)->unk530 = lbl_803E5C38;
    ((SnowBikeState*)state)->unk534 = lbl_803E5BF4;
    fz = lbl_803E5AE8;
    ((SnowBikeSetTypeState*)state)->unk414 = fz;
    ((SnowBikeState*)state)->unk584 = fz;
    ((SnowBikeState*)state)->localVelXDamp = lbl_803E5BFC;
    ((SnowBikeState*)state)->distanceScaleDamp = lbl_803E5BE4;
    ((SnowBikeState*)state)->turnVelScale = lbl_803E5B20;
    ((SnowBikeState*)state)->turnForceGain = lbl_803E5AF8;
    ((SnowBikeState*)state)->unk558 = lbl_803E5BA8;
    ((SnowBikeState*)state)->unk56C = lbl_803E5C00;
    flags = (DRcradleSnowBikeFlags*)(state + 0x428);
    flags->resetLatch = 0;
    ((SnowBikeState*)state)->unk430 = fz;
    fa = ((SnowBikeState*)state)->baseVelLimitX;
    ((SnowBikeState*)state)->velLimitX = fa;
    ((SnowBikeState*)state)->localVelXLimit = fa;
    fb = ((SnowBikeState*)state)->baseVelLimitY;
    ((SnowBikeState*)state)->velLimitY = fb;
    ((SnowBikeState*)state)->localVelYLimit = fb;
    fc = ((SnowBikeState*)state)->baseVelLimitZ;
    ((SnowBikeState*)state)->velLimitZ = fc;
    ((SnowBikeState*)state)->distanceScaleLimit = fc;
    flags->pathActive = 0;
    flags->impulseLatch = 0;
    *(u32*)(state + 0x42c) = 0;
    ((SnowBikeState*)state)->collisionFxTimer = fz;
    ((SnowBikeState*)state)->collisionFxDamping = lbl_803E5AEC;
}
#pragma dont_inline reset

void fn_801EC928(int obj, int state)
{
    f32 fa, fz;
    ((SnowBikeState*)state)->liftAccel = lbl_803E5C3C;
    ((SnowBikeState*)state)->unk530 = lbl_803E5C38;
    ((SnowBikeState*)state)->unk534 = lbl_803E5BF4;
    ((SnowBikeState*)state)->unk538 = lbl_803E5B74;
    ((SnowBikeState*)state)->unk53C = lbl_803E5C14;
    ((SnowBikeState*)state)->localVelXDamp = lbl_803E5BFC;
    ((SnowBikeState*)state)->distanceScaleDamp = lbl_803E5BE4;
    ((SnowBikeState*)state)->turnVelScale = lbl_803E5B20;
    ((SnowBikeState*)state)->turnForceGain = lbl_803E5AF8;
    fa = lbl_803E5C40;
    ((SnowBikeState*)state)->localVelXDampTarget = fa;
    ((SnowBikeState*)state)->distanceScaleDampTarget = fa;
    ((SnowBikeState*)state)->unk554 = lbl_803E5C44;
    ((SnowBikeState*)state)->unk550 = lbl_803E5C10;
    ((SnowBikeState*)state)->unk570 = lbl_803E5BB8;
    fz = lbl_803E5BA8;
    ((SnowBikeState*)state)->unk558 = fz;
    ((SnowBikeState*)state)->unk578 = lbl_803E5B8C;
    ((SnowBikeState*)state)->unk574 = lbl_803E5BB0;
    ((SnowBikeState*)state)->unk56C = lbl_803E5C00;
    ((SnowBikeState*)state)->collisionBounceScale = fz;
}

void SnowBike_setType(int obj, int type)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    u32 bit;
    ((SnowBikeSetTypeState*)state)->bikeType = type;
    if (type == 2)
    {
        GameBit_Set(((SnowBikeSetTypeState*)state)->completionGameBit, 1);
        fn_801EC870(obj, state);
        bit = (((SnowBikeSetTypeState*)state)->flags >> 5) & 1;
        if (bit != 0)
        {
            ((SnowBikeSetTypeState*)state)->airMeterMax = lbl_803E5B90;
            ((SnowBikeSetTypeState*)state)->airDrainRate = lbl_803E5AEC;
            ((SnowBikeSetTypeState*)state)->airMeterCurrent = lbl_803E5B94;
            if (((SnowBikeSetTypeState*)state)->bikeType == 2)
            {
                (*gGameUIInterface)->initAirMeter((int)((SnowBikeSetTypeState*)state)->airMeterMax, 0x5cd);
                (*gGameUIInterface)->airMeterSetRatio(lbl_803E5B98);
            }
        }
        if (((GameObject*)obj)->anim.seqId == 0x72)
        {
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lateralResponseWeight = 0x14;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->axialResponseWeight = 0x14;
        }
    }
}

void SnowBike_func12(int obj, f32* outFloat, s32* outBool)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    f32 value, r;
    *outFloat = ((SnowBikeMountState*)state)->unk414 / lbl_803E5C48;
    value = *outFloat;
    *outFloat = (value < lbl_803E5B70) ? lbl_803E5B70 : ((value > lbl_803E5AEC) ? lbl_803E5AEC : value);
    *outBool = ((SnowBikeMountState*)state)->unk414 < lbl_803E5AE8;
}

f32 SnowBike_func13(int obj, f32* out)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    f32 r;
    *out = lbl_803E5BB8;
    r = sqrtf(((SnowBikeMountState*)state)->velocityZ * ((SnowBikeMountState*)state)->velocityZ
        + (((SnowBikeMountState*)state)->velocityX * ((SnowBikeMountState*)state)->velocityX
            + ((SnowBikeMountState*)state)->velocityY * ((SnowBikeMountState*)state)->velocityY));
    r = r * lbl_803E5BA8;
    if (r > lbl_803E5AEC)
    {
        r = lbl_803E5AEC;
    }
    return r;
}

u32 SnowBike_setScale(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    u32 bit = (((SnowBikeMountState*)state)->flags >> 1) & 1;
    if (bit != 0)
    {
        return 0;
    }
    return ((SnowBikeMountState*)state)->unk420;
}

void fn_801EC9BC(int obj)
{
    (*gCheckpointInterface)
        ->getRouteRank((CheckpointRankItem*)(*(int*)&((GameObject*)obj)->extra + 0x28));
}

u32 fn_801EC9F4(int obj)
{
    int result =
        (*gCheckpointInterface)
            ->getRouteRank((CheckpointRankItem*)(*(int*)&((GameObject*)obj)->extra + 0x28));
    if (result == 3)
    {
        if (lbl_803DC0BC == -1)
        {
            return 1;
        }
    }
    return (u32)__cntlzw(lbl_803DC0BC - 1 - result) >> 5;
}

void SnowBike_free(int obj)
{
    char* p;
    int i;
    u32 bit;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, SNOWBIKE_OBJGROUP);
    i = 0;
    p = (char*)state;
    for (; i < 9; i++)
    {
        mm_free(*(void**)(p + 0x4c8));
        p += 8;
    }
    bit = (((SnowBikeMountState*)state)->flags >> 5) & 1;
    if (bit != 0)
    {
        (*gGameUIInterface)->airMeterSetShutdown();
    }
}

s32 SnowBike_func14(int* obj) { return ((SnowBikeState*)((GameObject*)obj)->extra)->unk422; }
s32 SnowBike_getType(int* obj) { return ((SnowBikeState*)((GameObject*)obj)->extra)->riderMode; }

void SnowBike_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    void* path;

    path = ((GameObject*)obj)->extra;
    fn_801E991C(obj, path);
    if (visible == -1)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E5AEC);
        ObjPath_GetPointWorldPosition(obj, 0, (char*)path + 0x3e8, (char*)path + 0x3ec, (char*)path + 0x3f0, 0);
    }
    else
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E5AEC);
        ObjPath_GetPointWorldPosition(obj, 0, (char*)path + 0x3e8, (char*)path + 0x3ec, (char*)path + 0x3f0, 0);
    }
}

typedef struct
{
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} HaloSnowBikeFlags;

void SnowBike_hitDetect(int obj)
{
    SnowBikeState* state;
    u8* other;
    int vol;
    f32 mag;
    f32 k;
    f32 k2;
    f32 value;
    f32 clamped;
    f32 limit;
    f32 dummy;

    state = ((GameObject*)obj)->extra;
    other = *(u8**)((GameObject*)obj)->anim.hitReactState;
    if (((GameObject*)obj)->pendingParentObj != NULL)
    {
        return;
    }
    if (state->riderMode == 2)
    {
        fn_801EB940(obj, (u8*)state);
        state->savedRotY = ((GameObject*)obj)->anim.rotY;
        state->savedRotZ = ((GameObject*)obj)->anim.rotZ;
        ((GameObject*)obj)->anim.rotY = (f32)((GameObject*)obj)->anim.rotY + state->haloPitchDrift;
        ((GameObject*)obj)->anim.rotZ = (f32)((GameObject*)obj)->anim.rotZ + (state->unk410 + state->haloDriftB);
    }
    if (state->unk3D9 == 4 || state->unk3D6 != 0)
    {
        ((GameObject*)obj)->anim.velocityY = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)
            ->anim.previousLocalPosY);
        state->localVelY = ((GameObject*)obj)->anim.velocityY;
    }
    if (state->unk3D6 == 0)
    {
        if ((((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags & 8) != 0 && arrayIndexOf(gSnowBikeHitObjectIdTable, 10, ((GameObject*)other)->anim.seqId) == -1)
        {
        }
        else
        {
            if (*(void**)&state->linkedObj == NULL)
            {
                goto clamp;
            }
            if (!(state->collisionFxDamping <= lbl_803E5AEC))
            {
                goto clamp;
            }
        }
    }
    mag = PSVECMag((f32*)(obj + 0x24));
    if (mag > lbl_803E5AEC)
    {
        if (!((HaloSnowBikeFlags*)&state->flags428)->b02)
        {
            doRumble(lbl_803E5BC4 * mag);
        }
        state->unk430 = state->unk430 * lbl_803E5BBC;
        if (((GameObject*)obj)->anim.seqId == 114 || ((GameObject*)obj)->anim.seqId == 908)
        {
            vol = (int)(lbl_803E5C4C * mag);
            if (vol > 80)
            {
                vol = 80;
            }
            else if (vol < 30)
            {
                vol = 30;
            }
            if (Sfx_IsPlayingFromObjectChannel(obj, 32) == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_tr_jbike_bombbeep);
                Sfx_SetObjectSfxVolume(obj, SFXTRIG_tr_jbike_bombbeep, vol, lbl_803E5B28);
            }
        }
    }
    if (!((HaloSnowBikeFlags*)&state->flags428)->b02 && mag > lbl_803E5BC4)
    {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(mag * lbl_803E5AF8);
    }
    if (*(void**)&state->linkedObj != NULL)
    {
        k = lbl_803E5C00;
        OSReport(&sSnowBikeVelDebugFmt, mag);
        if (((GameObject*)state->linkedObj)->anim.seqId == 909
            || ((GameObject*)state->linkedObj)->anim.seqId == 910
            || ((GameObject*)state->linkedObj)->anim.seqId == 1236)
        {
            k = lbl_803E5B88;
        }
        ((GameObject*)obj)->anim.velocityX = k * (oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject
            *)obj)->anim.previousLocalPosX));
        ((GameObject*)obj)->anim.velocityZ = k * (oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject
            *)obj)->anim.previousLocalPosZ));
    }
    else
    {
        k2 = lbl_803E5B88;
        ((GameObject*)obj)->anim.velocityX = k2 * (oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject
            *)obj)->anim.previousLocalPosX));
        ((GameObject*)obj)->anim.velocityZ = k2 * (oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject
            *)obj)->anim.previousLocalPosZ));
    }
    Matrix_TransformPoint((f32*)((u8*)state + 0x12c), ((GameObject*)obj)->anim.velocityX, lbl_803E5AE8,
                          ((GameObject*)obj)->anim.velocityZ,
                          &state->localVelX, &dummy, &state->distanceScale);
clamp:
    {
        f32 limit;
        f32 value = state->localVelX;
        f32 clamped;
        limit = state->localVelXLimit;
        if (value < -limit)
        {
            clamped = -limit;
        }
        else if (value > limit)
        {
            clamped = limit;
        }
        else
        {
            clamped = value;
        }
        state->localVelX = clamped;
    }
    if (state->localVelX < lbl_803E5B8C && state->localVelX > lbl_803E5BA4)
    {
        state->localVelX = lbl_803E5AE8;
    }
    value = state->localVelY;
    limit = state->localVelYLimit;
    if (value < -limit)
    {
        clamped = -limit;
    }
    else if (value > lbl_803E5AEC)
    {
        clamped = lbl_803E5AEC;
    }
    else
    {
        clamped = value;
    }
    state->localVelY = clamped;
    if (state->localVelY < lbl_803E5B8C && state->localVelY > lbl_803E5BA4)
    {
        state->localVelY = lbl_803E5AE8;
    }
    {
        f32 limit;
        f32 value = state->distanceScale;
        f32 clamped;
        limit = state->distanceScaleLimit;
        if (value < -limit)
        {
            clamped = -limit;
        }
        else if (value > limit)
        {
            clamped = limit;
        }
        else
        {
            clamped = value;
        }
        state->distanceScale = clamped;
    }
    if (state->distanceScale < lbl_803E5B8C && state->distanceScale > lbl_803E5BA4)
    {
        state->distanceScale = lbl_803E5AE8;
    }
    state->refPosX = ((GameObject*)obj)->anim.localPosX;
    state->refPosY = ((GameObject*)obj)->anim.localPosY;
    state->refPosZ = ((GameObject*)obj)->anim.localPosZ;
    state->linkedObj = 0;
}

void SnowBike_release(void)
{
    if (lbl_803DDC60 != 0)
    {
        textureFree(lbl_803DDC60);
        lbl_803DDC60 = 0;
    }
}

void SnowBike_initialise(void)
{
    if (lbl_803DDC60 == 0)
    {
        lbl_803DDC60 = textureLoadAsset(0x186);
    }
}


typedef struct
{
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} SnowBikeFlags;

#pragma inline_max_size(4000)
static inline void SnowBike_initBody(int obj, u8* params, int flag)
{
    extern void fn_801EC928(int obj, u8* state); /* #57 */
    f32 fv;
    f32 fz;
    s16 rot;
    int i;
    u8* path;
    u8* alloc;
    u32 pathParam;
    u8* state;
    char* base = lbl_803284E0;

    pathParam = lbl_803E5AE0;
    state = ((GameObject*)obj)->extra;

    if (((GameObject*)obj)->anim.mapEventSlot == 0x13)
    {
        alloc = mmAlloc(36, 5, 0);
        memcpy(alloc, params, 36);
        *(u8**)&((GameObject*)obj)->anim.placementData = alloc;
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_OWNS_PLACEMENT_DATA;
        Obj_ClearModelSlotIndex(obj);
    }
    rot = params[0x18] << 8;
    ((SnowBikeState*)state)->yawCurrent = rot;
    ((SnowBikeState*)state)->yaw = rot;
    ((GameObject*)obj)->anim.rotX = rot;
    fn_801EC928(obj, state);
    if (flag == 0)
    {
        if (((SnowBikeFlags*)(state + 0x428))->b20)
        {
            ((SnowBikeState*)state)->airMeterMax = lbl_803E5B90;
            ((SnowBikeState*)state)->airDrainRate = lbl_803E5AEC;
            ((SnowBikeState*)state)->airMeterCurrent = lbl_803E5B94;
            if (((SnowBikeState*)state)->riderMode == 2)
            {
                (*gGameUIInterface)->initAirMeter((int)((SnowBikeState*)state)->airMeterMax, 1485);
                (*gGameUIInterface)->airMeterSetRatio(lbl_803E5B98);
            }
        }
    }
    if (params[0x19] != 0)
    {
        ((SnowBikeFlags*)(state + 0x428))->b02 = 1;
    }
    ((SnowBikeState*)state)->checkpointIndexA = -1;
    ((SnowBikeState*)state)->checkpointIndexB = -1;
    ((SnowBikeState*)state)->checkpointIndexC = -1;
    ((SnowBikeState*)state)->unk05C = params[0x1c];
    ((SnowBikeState*)state)->unk05D = params[0x1d];
    ((SnowBikeState*)state)->posSnapshotX = ((GameObject*)obj)->anim.localPosX;
    ((SnowBikeState*)state)->posSnapshotY = ((GameObject*)obj)->anim.localPosY;
    ((SnowBikeState*)state)->posSnapshotZ = ((GameObject*)obj)->anim.localPosZ;
    ((GameObject*)obj)->animEventCallback = SnowBike_animEventCallback;
    ObjGroup_AddObject(obj, SNOWBIKE_OBJGROUP);
    if (flag == 0)
    {
        i = 0;
        for (path = state; i < 9; i++)
        {
            *(u8**)(path + 0x4c8) = mmAlloc(1600, 26, 0);
            path += 8;
        }
    }
    ((SnowBikeState*)state)->homePosX = ((GameObject*)obj)->anim.worldPosX;
    ((SnowBikeState*)state)->homePosY = ((GameObject*)obj)->anim.worldPosY;
    ((SnowBikeState*)state)->homePosZ = ((GameObject*)obj)->anim.worldPosZ;
    ((SnowBikeState*)state)->pathProgress = lbl_803E5AE8;
    ((SnowBikeState*)state)->unk448 = *(s16*)(params + 0x1a);
    ((SnowBikeState*)state)->gameBitId = *(s16*)(params + 0x1e);
    if (GameBit_Get(((SnowBikeState*)state)->gameBitId) != 0)
    {
        ((SnowBikeFlags*)(state + 0x428))->b04 = 1;
    }
    ((SnowBikeState*)state)->unk438 = lbl_803E5B1C;
    fz = lbl_803E5AE8;
    ((SnowBikeState*)state)->unk3F4 = fz;
    ((SnowBikeState*)state)->unk3F8 = fz;
    ((SnowBikeState*)state)->unk018 = lbl_803E5C48;
    ((SnowBikeState*)state)->unk01C = fz;
    ((SnowBikeState*)state)->unk020 = lbl_803E5BC4;
    ((SnowBikeState*)state)->unk024 = lbl_803E5C50;
    ((SnowBikeState*)state)->collisionHitType = -1;
    fv = lbl_803E5B98;
    ((SnowBikeState*)state)->velLimitX = fv;
    ((SnowBikeState*)state)->velLimitY = fv;
    ((SnowBikeState*)state)->modelId = 0x436;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x72:
    default:
        ((SnowBikeState*)state)->bikeType = 1;
        ((SnowBikeState*)state)->velLimitZ = lbl_803E5C50;
        ((SnowBikeState*)state)->modelId = 282;
        break;
    case 0x16c:
        ((SnowBikeState*)state)->bikeType = 1;
        ((SnowBikeState*)state)->bikeVariant = 0;
        ((SnowBikeState*)state)->unk01C = lbl_803E5B14;
        ((SnowBikeState*)state)->unk018 = lbl_803E5C54;
        ((SnowBikeState*)state)->collisionHitType = 1;
        ((SnowBikeState*)state)->velLimitZ = lbl_803E5AF0;
        break;
    case 0x16f:
        ((SnowBikeState*)state)->bikeType = 1;
        ((SnowBikeState*)state)->unk058 = 1;
        ((SnowBikeState*)state)->bikeVariant = 1;
        ((SnowBikeState*)state)->collisionHitType = 2;
        ((SnowBikeState*)state)->velLimitZ = lbl_803E5AF0;
        break;
    case 0x38c:
        ((SnowBikeState*)state)->bikeType = 0;
        ((SnowBikeState*)state)->velLimitZ = lbl_803DC0C4;
        ((SnowBikeState*)state)->modelId = 282;
        break;
    case 0x38d:
        ((SnowBikeState*)state)->bikeType = 0;
        ((SnowBikeState*)state)->bikeVariant = 0;
        ((SnowBikeState*)state)->unk01C = lbl_803E5B14;
        ((SnowBikeState*)state)->unk018 = lbl_803E5C54;
        ((SnowBikeState*)state)->velLimitZ = lbl_803E5C58 * lbl_803DC0C0;
        break;
    case 0x38e:
        ((SnowBikeState*)state)->bikeType = 0;
        ((SnowBikeState*)state)->bikeVariant = 1;
        ((SnowBikeState*)state)->unk01C = lbl_803E5B48;
        ((SnowBikeState*)state)->unk018 = lbl_803E5C5C;
        ((SnowBikeState*)state)->velLimitZ = lbl_803E5C60 * lbl_803DC0C0;
        break;
    case 0x4d4:
        ((SnowBikeState*)state)->bikeType = 0;
        ((SnowBikeState*)state)->bikeVariant = 2;
        ((SnowBikeState*)state)->unk01C = lbl_803E5B48;
        ((SnowBikeState*)state)->unk018 = lbl_803E5C5C;
        ((SnowBikeState*)state)->velLimitZ = lbl_803DC0C0;
        break;
    }
    fv = ((SnowBikeState*)state)->velLimitX;
    ((SnowBikeState*)state)->localVelXLimit = fv;
    ((SnowBikeState*)state)->baseVelLimitX = fv;
    fv = ((SnowBikeState*)state)->velLimitY;
    ((SnowBikeState*)state)->localVelYLimit = fv;
    ((SnowBikeState*)state)->baseVelLimitY = fv;
    fv = ((SnowBikeState*)state)->velLimitZ;
    ((SnowBikeState*)state)->distanceScaleLimit = fv;
    ((SnowBikeState*)state)->baseVelLimitZ = fv;
    ((SnowBikeState*)state)->gameBitPtr = (char*)((int)base + 0xa4 + ((SnowBikeState*)state)->bikeType * 6);
    if (((SnowBikeState*)state)->bikeType == 0)
    {
        if (!((SnowBikeFlags*)(state + 0x428))->b02)
        {
            ((SnowBikeFlags*)(state + 0x428))->b20 = 1;
            ((SnowBikeState*)state)->airMeterRefillTimer = lbl_803E5AE8;
        }
        ((SnowBikeState*)state)->unk538 = lbl_803E5C64;
    }
    else
    {
        ((SnowBikeState*)state)->unk538 = lbl_803E5B74;
    }
    path = state + 0x178;
    path[0x25b] = 1;
    (*gPathControlInterface)->init(path, 0, 0x48607, 1);
    (*gPathControlInterface)->setup(path, 4, base, base + 0x30, &pathParam);
    if (((SnowBikeFlags*)(state + 0x428))->b02 && ((SnowBikeState*)state)->collisionHitType != -1)
    {
        curves_setLocalPointCollisionEx((CurvesCollisionState*)path, 1, (f32*)(base + 0x40),
                                        &lbl_803DC0B8, 8, ((SnowBikeState*)state)->collisionHitType);
    }
    else
    {
        (*gPathControlInterface)->setLocalPointCollision(path, 1, base + 0x40, &lbl_803DC0B8, 8);
    }
    path[0x264] = lbl_803E5C68 + lbl_803DC0B8;
    (*gPathControlInterface)->attachObject((void*)obj, path);
}

void SnowBike_init(int obj, u8* params, int flag)
{
    SnowBike_initBody(obj, params, flag);
}
#pragma inline_max_size reset

typedef struct
{
    s16 rot[3];
    f32 quad[4];
} SBRotQuad;

#pragma opt_common_subs off
void SnowBike_update(int obj)
{
    extern void fn_801EC7A0(int obj, u8* state); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    f32 mtx1[16];
    f32 mtx2[16];
    SBRotQuad rq1;
    SBRotQuad rq2;
    f32 vec1[3];
    f32 vec2[3];
    f32 dummy1;
    f32 dummy2;
    s8 mode;
    int t;
    f32 fz;
    f32 damp;
    f32 value;
    f32 clamped;

    if (((GameObject*)obj)->anim.mapEventSlot == -1)
    {
        if (GameBit_Get(0x1fa) != 0)
        {
            ((SnowBikeState*)state)->unk420 = 0;
        }
        if (GameBit_Get(0x1fb) != 0)
        {
            Obj_SetModelSlotIndex(obj, 0x13);
        }
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    ((GameObject*)obj)->anim.rotY = ((SnowBikeState*)state)->savedRotY;
    ((GameObject*)obj)->anim.rotZ = ((SnowBikeState*)state)->savedRotZ;
    if (((SnowBikeFlags*)(state + 0x428))->b04 || GameBit_Get(((SnowBikeState*)state)->gameBitId) != 0)
    {
        ((SnowBikeFlags*)(state + 0x428))->b04 = 1;
        return;
    }
    mode = ((SnowBikeState*)state)->riderMode;
    switch (mode)
    {
    case 0:
        {
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
                {
                    ((SnowBikeState*)state)->unk420 = 1;
                }
                else
                {
                    ((SnowBikeState*)state)->unk420 = 0;
                }
                Sfx_StopObjectChannel(obj, 0x57);
            }
        }
        break;
    case 2:
        {
            fn_801EAE4C(obj, state);
            if (((SnowBikeFlags*)(state + 0x428))->b02)
            {
                if (drshackle_updateAttachedPosition(obj, state) != 0)
                {
                    fn_801EBD60(obj, state);
                    fn_801EC7A0(obj, state);
                    if (((SnowBikeState*)state)->collisionFxTimer != lbl_803E5AE8)
                    {
                        PSVECScale((f32*)(state + 0x464), (f32*)(state + 0x47c),
                                   ((SnowBikeState*)state)->collisionFxDamping);
                        PSVECScale((f32*)(state + 0x494), (f32*)(state + 0x494),
                                   ((SnowBikeState*)state)->collisionFxDamping);
                        ((SnowBikeState*)state)->collisionFxTimer -= timeDelta;
                        if (((SnowBikeState*)state)->collisionFxTimer <= lbl_803E5AE8)
                        {
                            if (Rcp_GetMotionBlurEnabled() != 0)
                            {
                                setMotionBlur(0, lbl_803E5AE8);
                            }
                            ((SnowBikeState*)state)->collisionFxTimer = lbl_803E5AE8;
                        }
                    }
                    else
                    {
                        ((SnowBikeState*)state)->localVelXLimit = ((SnowBikeState*)state)->velLimitX;
                        ((SnowBikeState*)state)->localVelYLimit = ((SnowBikeState*)state)->velLimitY;
                        ((SnowBikeState*)state)->distanceScaleLimit = ((SnowBikeState*)state)->velLimitZ;
                    }
                    fz = lbl_803E5AE8;
                    rq1.quad[1] = fz;
                    rq1.quad[2] = fz;
                    rq1.quad[3] = fz;
                    rq1.quad[0] = lbl_803E5AEC;
                    rq1.rot[0] = -((SnowBikeState*)state)->yaw;
                    rq1.rot[1] = -((GameObject*)obj)->anim.rotY;
                    rq1.rot[2] = -((GameObject*)obj)->anim.rotZ;
                    mtxRotateByVec3s(mtx1, rq1.rot);
                    Matrix_TransformPoint(mtx1, lbl_803E5AE8,
                                          ((SnowBikeState*)state)->liftAccel * ((SnowBikeState*)state)->turnForceGain,
                                          lbl_803E5AE8, &vec1[0], &dummy1, &vec1[2]);
                    vec1[0] = vec1[0] * ((SnowBikeState*)state)->turnVelScale;
                    vec1[1] = lbl_803E5AE8;
                    PSVECScale(vec1, vec1, timeDelta);
                    PSVECAdd((f32*)(state + 0x494), vec1, (f32*)(state + 0x494));
                    ((SnowBikeState*)state)->localVelY = ((SnowBikeState*)state)->liftAccel * timeDelta + ((SnowBikeState*)
                        state)->localVelY;
                    damp = powfBitEstimate(((SnowBikeState*)state)->localVelXDamp, timeDelta);
                    ((SnowBikeState*)state)->localVelX *= damp;
                    damp = powfBitEstimate(((SnowBikeState*)state)->distanceScaleDamp, timeDelta);
                    ((SnowBikeState*)state)->distanceScale *= damp;
                    fn_801EC1AC(obj, (int)state);
                    Matrix_TransformPoint((f32*)(state + 0xec), ((SnowBikeState*)state)->localVelX,
                                          ((SnowBikeState*)state)->localVelY, ((SnowBikeState*)state)->distanceScale,
                                          &((GameObject*)obj)->anim.velocityX, &((GameObject*)obj)->anim.velocityY,
                                          &((GameObject*)obj)->anim.velocityZ);
                    objApplyVelocity(obj);
                }
            }
            else
            {
                setAButtonIcon(0x10);
                setBButtonIcon(0x11);
                ((SnowBikeState*)state)->stickX = padGetStickX(0);
                ((SnowBikeState*)state)->stickY = (f32)padGetStickY(0);
                ((SnowBikeState*)state)->buttonsHeld = getButtonsHeld(0);
                ((SnowBikeState*)state)->buttonsJustPressed = getButtonsJustPressed(0);
                ((SnowBikeState*)state)->buttonsJustPressedIfNotBusy = getButtonsJustPressedIfNotBusy(0);
                ((SnowBikeState*)state)->steerAngleDeg = (f32)(u16)
                getAngle(((SnowBikeState*)state)->stickX, (f32) - (int)((SnowBikeState*)state)->stickY) / gSnowBikeBamToDeg;
                ((SnowBikeState*)state)->stickX = ((SnowBikeState*)state)->stickX / lbl_803E5B6C;
                value = ((SnowBikeState*)state)->stickX;
                if (value < lbl_803E5B70)
                {
                    clamped = lbl_803E5B70;
                }
                else if (value > lbl_803E5AEC)
                {
                    clamped = lbl_803E5AEC;
                }
                else
                {
                    clamped = value;
                }
                ((SnowBikeState*)state)->stickX = clamped;
                fn_801EBD60(obj, state);
                fn_801EC7A0(obj, state);
                if (((SnowBikeState*)state)->collisionFxTimer != lbl_803E5AE8)
                {
                    PSVECScale((f32*)(state + 0x464), (f32*)(state + 0x47c),
                               ((SnowBikeState*)state)->collisionFxDamping);
                    PSVECScale((f32*)(state + 0x494), (f32*)(state + 0x494),
                               ((SnowBikeState*)state)->collisionFxDamping);
                    ((SnowBikeState*)state)->collisionFxTimer -= timeDelta;
                    if (((SnowBikeState*)state)->collisionFxTimer <= lbl_803E5AE8)
                    {
                        if (Rcp_GetMotionBlurEnabled() != 0)
                        {
                            setMotionBlur(0, lbl_803E5AE8);
                        }
                        ((SnowBikeState*)state)->collisionFxTimer = lbl_803E5AE8;
                    }
                }
                else
                {
                    ((SnowBikeState*)state)->localVelXLimit = ((SnowBikeState*)state)->velLimitX;
                    ((SnowBikeState*)state)->localVelYLimit = ((SnowBikeState*)state)->velLimitY;
                    ((SnowBikeState*)state)->distanceScaleLimit = ((SnowBikeState*)state)->velLimitZ;
                }
                fz = lbl_803E5AE8;
                rq2.quad[1] = fz;
                rq2.quad[2] = fz;
                rq2.quad[3] = fz;
                rq2.quad[0] = lbl_803E5AEC;
                rq2.rot[0] = -((SnowBikeState*)state)->yaw;
                rq2.rot[1] = -((GameObject*)obj)->anim.rotY;
                rq2.rot[2] = -((GameObject*)obj)->anim.rotZ;
                mtxRotateByVec3s(mtx2, rq2.rot);
                Matrix_TransformPoint(mtx2, lbl_803E5AE8,
                                      ((SnowBikeState*)state)->liftAccel * ((SnowBikeState*)state)->turnForceGain, lbl_803E5AE8,
                                      &vec2[0], &dummy2, &vec2[2]);
                vec2[0] = vec2[0] * ((SnowBikeState*)state)->turnVelScale;
                vec2[1] = lbl_803E5AE8;
                PSVECScale(vec2, vec2, timeDelta);
                PSVECAdd((f32*)(state + 0x494), vec2, (f32*)(state + 0x494));
                ((SnowBikeState*)state)->localVelY = ((SnowBikeState*)state)->liftAccel * timeDelta + ((SnowBikeState*)state)
                    ->localVelY;
                damp = powfBitEstimate(((SnowBikeState*)state)->localVelXDamp, timeDelta);
                ((SnowBikeState*)state)->localVelX *= damp;
                damp = powfBitEstimate(((SnowBikeState*)state)->distanceScaleDamp, timeDelta);
                ((SnowBikeState*)state)->distanceScale *= damp;
                fn_801EC1AC(obj, (int)state);
                Matrix_TransformPoint((f32*)(state + 0xec), ((SnowBikeState*)state)->localVelX,
                                      ((SnowBikeState*)state)->localVelY, ((SnowBikeState*)state)->distanceScale,
                                      &((GameObject*)obj)->anim.velocityX, &((GameObject*)obj)->anim.velocityY,
                                      &((GameObject*)obj)->anim.velocityZ);
                objApplyVelocity(obj);
            }
            fn_801EB0D4(obj, state);
            fn_801EA240(obj, state, ((SnowBikeState*)state)->distanceScale,
                        (int)(lbl_803E5BA0 * -((SnowBikeState*)state)->unk430), state + 0x461, 7);
            fn_801EB634(obj, state);
            ((GameObject*)obj)->anim.rotX = ((SnowBikeState*)state)->yaw;
        }
        break;
    }
}
#pragma opt_common_subs reset

s16 gSnowBikeHitObjectIdTable[26] = {
    0, 365, 0, 368, 0, 364, 0, 367, 0, 905, 0, 906, 0,
    1235, 0, 909, 0, 910, 0, 1236, 1175, 1176, 1180, 930, 931, 1180,
};

int gSnowBikeMountRomListTable[6] = { 0x30C60, 0x30C60, 0x30C60, 0xC9E, 0xC9F, 0xCB3 };
