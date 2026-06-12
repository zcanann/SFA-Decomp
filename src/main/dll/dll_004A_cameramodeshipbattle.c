/* === moved from main/dll/CAM/dll_5F.c [8010BF08-8010C0D8) (TU re-split, docs/boundary_audit.md) === */
#include "main/camera_interface.h"
#include "main/dll/CAM/camcombat_state.h"
#include "main/mm.h"



/*
 * --INFO--
 *
 * Function: CameraModeTestStrength_update
 * EN v1.0 Address: 0x8010B424
 * EN v1.0 Size: 2392b
 * EN v1.1 Address: 0x8010B6C0
 * EN v1.1 Size: 1652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: CameraModeTestStrength_init
 * EN v1.0 Address: 0x8010BD7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010BD34
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */


void CameraModeCombat_copyToCurrent_nop(void);

extern CameraModeCombatState* lbl_803DD568;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
extern f32 lbl_803E18C8;
extern f32 timeDelta;
extern void Rcp_DisableBlurFilter(void);

/*
 * --INFO--
 *
 * Function: fn_8010BF08
 * EN v1.0 Address: 0x8010BF08
 * EN v1.0 Size: 348b
 */
typedef struct
{
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} CamPathEntry;

void fn_8010BF08(int control, float* outX, float* outY, float* outZ, void* inFloatPtr);

/*
 * --INFO--
 *
 * Function: CameraModeCombat_free
 * EN v1.0 Address: 0x8010C068
 * EN v1.0 Size: 112b
 */
typedef struct
{
    u8 flag80 : 1;
} CamByte143;

void CameraModeCombat_free(int obj);

#include "main/dll/CAM/camdrakor.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camclimb_state.h"
#include "main/dll/CAM/camcombat_state.h"
#include "main/dll/CAM/camshipbattle_state.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"


extern void* FUN_800069a8();
extern void camcontrol_traceMove(f32 radius, f32* from, void* to, f32* out, void* work, int a,
                                 int b, int c);
extern undefined4 Camera_GetCurrentViewSlot();
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern uint fn_8029630C(int obj);
extern int objAnimFn_80296328(int obj);
extern undefined4 cameraGetPrevPos2();

extern s32 lbl_803DD56C;
extern CameraModeShipBattleState* lbl_803DD570;
extern f64 lbl_803E1918;
extern f32 lbl_803E18CC;
extern f32 lbl_803E18D0;
extern f32 lbl_803E18D4;
extern f32 lbl_803E18D8;
extern f32 lbl_803E18DC;
extern f32 lbl_803E18E0;
extern f32 lbl_803E18E4;
extern f32 lbl_803E18E8;
extern f32 lbl_803E18EC;
extern f32 lbl_803E18F0;
extern f32 lbl_803E18F4;
extern f32 lbl_803E18F8;
extern f32 lbl_803E18FC;
extern f32 lbl_803E1900;
extern f32 lbl_803E1904;
extern f32 lbl_803E1908;
extern f32 lbl_803E190C;
extern f32 lbl_803E1910;
extern f32 lbl_803E1920;
extern f32 lbl_803E1924;
extern f32 lbl_803E1928;
extern f32 lbl_803E192C;
extern f32 lbl_803E1930;
extern f32 lbl_803E1940;
extern f32 lbl_803E1948;
extern f32 lbl_803E194C;
extern f32 lbl_803E1950;
extern f32 lbl_803E1954;
extern f32 lbl_803E1958;
extern f32 lbl_803E195C;
extern f32 lbl_803E1960;
extern f32 lbl_803E1964;
extern f32 lbl_803E1968;
extern f32 lbl_803E196C;
extern f32 lbl_803E1970;
extern f32 lbl_803E1974;
extern f32 lbl_803E1978;
extern f32 lbl_803E197C;
extern f32 lbl_803E1980;

/*
 * --INFO--
 *
 * Function: CameraModeCombat_update
 * EN v1.0 Address: 0x8010C0D8
 * EN v1.0 Size: 3352b
 * EN v1.1 Address: 0x8010C374
 * EN v1.1 Size: 3204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    f32 pad0;
    f32 pad4;
    f32 pad8;
    f32 x;
    f32 y;
    f32 z;
} CombatPathPoint;

typedef struct
{
    u8 b80 : 1;
    u8 rest : 7;
} CombatCamFlags;

extern int getAngle(f32 dx, f32 dz);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern f32 powfBitEstimate(f32 a, f32 b);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern f32 PSVECMag(f32 * v);
extern void PSVECNormalize(f32 * v, f32 * out);
extern void PSVECScale(f32* v, f32* out, f32 s);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern void turnOnBlurFilter(f32 x, f32 y, f32 z, int a, int b);

void CameraModeCombat_update(short* cam);

/*
 * --INFO--
 *
 * Function: CameraModeCombat_init
 * EN v1.0 Address: 0x8010CDF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010CFF8
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeCombat_init(int camObj, undefined4 arg2, undefined4* args);


/*
 * --INFO--
 *
 * Function: CameraModeShipBattle_update
 * EN v1.0 Address: 0x8010CE20
 * EN v1.0 Size: 1580b
 * EN v1.1 Address: 0x8010D18C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int shipBattleFn_801eed24(int focus);

void CameraModeShipBattle_update(short* cam)
{
    f32 fa;
    f32 fb;
    f32 fc;
    f32 r;
    int m = 0;
    GameObject* focus = (GameObject*)((CameraObject*)cam)->anim.targetObj;
    if (focus != NULL)
    {
        m = shipBattleFn_801eed24((int)focus);
    }
    if (m != lbl_803DD570->mode)
    {
        if (m == 2)
        {
            fa = lbl_803E1948;
        }
        else
        {
            fa = lbl_803E194C;
        }
        if (m != 2 && m != 5)
        {
            fb = lbl_803E1950;
            fc = lbl_803E1954;
        }
        else
        {
            fb = lbl_803E1958;
            fc = lbl_803DD570->smoothedYOffset;
        }
        lbl_803DD570->mode = m;
        lbl_803DD570->lateralDelta = fa - lbl_803DD570->targetLateralOffset;
        lbl_803DD570->startLateralOffset = lbl_803DD570->targetLateralOffset;
        lbl_803DD570->verticalDelta = fb - (lbl_803DD570->verticalOffset + fc);
        lbl_803DD570->startVerticalOffset = lbl_803DD570->verticalOffset;
        lbl_803DD570->blendTimer = lbl_803E1954;
    }
    fa = lbl_803E195C;
    if (lbl_803DD570->blendTimer < lbl_803E195C)
    {
        lbl_803DD570->blendTimer = lbl_803E1960 * timeDelta + lbl_803DD570->blendTimer;
        if (lbl_803DD570->blendTimer > fa)
        {
            lbl_803DD570->blendTimer = fa;
        }
        lbl_803DD570->targetLateralOffset = lbl_803DD570->blendTimer * lbl_803DD570->lateralDelta + lbl_803DD570->
            startLateralOffset;
        lbl_803DD570->verticalOffset = lbl_803DD570->blendTimer * lbl_803DD570->verticalDelta + lbl_803DD570->
            startVerticalOffset;
    }
    if (m != 2 && m != 5)
    {
        lbl_803DD570->smoothedZOffset = -(((f32)focus->anim.rotZ / lbl_803E1964) * timeDelta - lbl_803DD570->
            smoothedZOffset);
        lbl_803DD570->smoothedYOffset = -(((f32)focus->anim.rotY / lbl_803E1968) * timeDelta - lbl_803DD570->
            smoothedYOffset);
        fc = lbl_803E196C;
        fa = lbl_803E196C * lbl_803DD570->smoothedZOffset;
        lbl_803DD570->smoothedZOffset = -(fa * timeDelta - lbl_803DD570->smoothedZOffset);
        fa = fc * lbl_803DD570->smoothedYOffset;
        lbl_803DD570->smoothedYOffset = -(fa * timeDelta - lbl_803DD570->smoothedYOffset);
        ((CameraObject*)cam)->anim.worldPosY = lbl_803DD570->smoothedYOffset + (focus->anim.worldPosY + lbl_803DD570->
            verticalOffset);
    }
    else
    {
        lbl_803DD570->smoothedZOffset = -(((f32)focus->anim.rotZ / lbl_803E1964) * timeDelta - lbl_803DD570->
            smoothedZOffset);
        lbl_803DD570->smoothedYOffset = -(((f32)focus->anim.rotY / lbl_803E1968) * timeDelta - lbl_803DD570->
            smoothedYOffset);
        fc = lbl_803E196C;
        fa = lbl_803E196C * lbl_803DD570->smoothedZOffset;
        lbl_803DD570->smoothedZOffset = -(fa * timeDelta - lbl_803DD570->smoothedZOffset);
        fa = fc * lbl_803DD570->smoothedYOffset;
        lbl_803DD570->smoothedYOffset = -(fa * timeDelta - lbl_803DD570->smoothedYOffset);
        ((CameraObject*)cam)->anim.worldPosY = lbl_803DD570->smoothedYOffset + (focus->anim.worldPosY + lbl_803DD570->
            verticalOffset);
    }
    ((CameraObject*)cam)->anim.worldPosX = (lbl_803E1970 + focus->anim.worldPosX) + lbl_803DD570->lateralOffset;
    ((CameraObject*)cam)->anim.worldPosZ = focus->anim.worldPosZ + lbl_803DD570->smoothedZOffset;
    cam[1] = 0x708;
    cam[0] = 0x4000;
    cam[2] = (s16)(-focus->anim.rotZ >> 3);
    ((CameraObject*)cam)->fov = lbl_803E1974;
    r = (lbl_803DD570->targetLateralOffset - lbl_803DD570->lateralOffset) / lbl_803E1978;
    if (r > lbl_803E197C)
    {
        r = lbl_803E197C;
    }
    else if (r < lbl_803E1980)
    {
        r = lbl_803E1980;
    }
    r = r * timeDelta;
    lbl_803DD570->lateralOffset = lbl_803DD570->lateralOffset + r;
    Obj_TransformWorldPointToLocal(((CameraObject*)cam)->anim.worldPosX, ((CameraObject*)cam)->anim.worldPosY,
                                   ((CameraObject*)cam)->anim.worldPosZ,
                                   &((CameraObject*)cam)->anim.localPosX, &((CameraObject*)cam)->anim.localPosY,
                                   &((CameraObject*)cam)->anim.localPosZ,
                                   *(int*)&((CameraObject*)cam)->anim.parent);
}

/*
 * --INFO--
 *
 * Function: CameraModeShipBattle_init
 * EN v1.0 Address: 0x8010D44C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010D534
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeShipBattle_init(void)
{
    float fval;
    u8 zero;

    if (lbl_803DD570 == (CameraModeShipBattleState*)0x0)
    {
        lbl_803DD570 = (CameraModeShipBattleState*)mmAlloc(sizeof(CameraModeShipBattleState), 0xf, 0);
    }
    fval = lbl_803E1954;
    lbl_803DD570->smoothedZOffset = lbl_803E1954;
    lbl_803DD570->smoothedYOffset = fval;
    lbl_803DD570->lateralOffset = lbl_803E1978;
    fval = lbl_803E194C;
    lbl_803DD570->startLateralOffset = lbl_803E194C;
    lbl_803DD570->targetLateralOffset = fval;
    lbl_803DD570->blendTimer = lbl_803E195C;
    zero = 0;
    lbl_803DD570->mode = zero;
    fval = lbl_803E1950;
    lbl_803DD570->startVerticalOffset = lbl_803E1950;
    lbl_803DD570->verticalOffset = fval;
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeCombat_release(void);

void CameraModeCombat_initialise(void);

void CameraModeShipBattle_copyToCurrent_nop(void)
{
}

void CameraModeShipBattle_release(void)
{
}

void CameraModeShipBattle_initialise(void)
{
}

void CameraModeClimb_copyToCurrent_nop(void);

/* fn_X(lbl); lbl = 0; */
void CameraModeShipBattle_free(void)
{
    mm_free(lbl_803DD570);
    lbl_803DD570 = 0;
}

void CameraModeClimb_free(void);
