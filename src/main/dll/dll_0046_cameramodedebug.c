#include "main/dll/CAM/camshipbattle5C.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camdebug_state.h"
#include "main/dll/CAM/dll_0045_camTalk.h"
#include "main/dll/CAM/camstatic_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/dll/CAM/dll_5B.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"

typedef struct CameraModeStaticPlacement
{
    u8 pad0[0x1C - 0x0];
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} CameraModeStaticPlacement;


extern u32 getButtonsHeld(int port);
extern char padGetCX(int port);
extern char padGetCY(int port);
extern uint getAngle();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern u8 framesThisStep;
extern ViewfinderState* lbl_803DD548;
extern CameraModeDebugState* lbl_803DD550;
extern CameraModeStaticState* lbl_803DD558;
extern f32 timeDelta;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern f32 lbl_803E17E0;
extern f32 lbl_803E17E4;
extern f32 lbl_803E17E8;
extern f32 lbl_803E17EC;
extern f32 lbl_803E17F0;
extern f32 lbl_803E17F4;
extern f32 lbl_803E17F8;
extern f32 lbl_803E17FC;
extern f32 lbl_803E1800;
extern f32 lbl_803E1804;
extern f32 lbl_803E1808;
extern f32 lbl_803E180C;
extern f32 lbl_803E1810;
extern f32 lbl_803E1814;
extern f32 lbl_803E1818;
extern f32 lbl_803E181C;
extern f32 lbl_803E1820;
extern f32 lbl_803E1824;
extern f32 lbl_803E1828;
extern f32 lbl_803E182C;
extern f32 lbl_803E1830;
extern f32 lbl_803E1840;
extern f32 lbl_803E1844;
extern f32 lbl_803E1848;
extern f32 lbl_803E184C;
extern f32 lbl_803E1850;
extern f32 lbl_803E1854;
extern f32 lbl_803E1858;
extern f32 lbl_803E185C;
extern f32 lbl_803E1860;
extern f32 lbl_803E1870;
extern f32 lbl_803E1878;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;


extern char padGetStickX(int port);
extern char padGetStickY(int port);
extern f32 interpolate(f32 v, f32 a, f32 b);
extern void fn_802961D4(short* obj, int v);
extern f32 Camera_GetFovY(void);
extern void viewFinderSetZoom(f32 fov);
extern void Sfx_StopFromObject(int obj, int sfxId);

/*
 * --INFO--
 *
 * Function: firstPersonDoControls
 * EN v1.0 Address: 0x8010847C
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: 0x80108718
 * EN v1.1 Size: 1024b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstPersonDoControls(short* obj);


/*
 * --INFO--
 *
 * Function: firstPersonEnter
 * EN v1.0 Address: 0x80108870
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108B18
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int fn_802966D4(int obj, int* out);

int firstPersonEnter(u8* cam, s16* p2);

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_copyToCurrent
 * EN v1.0 Address: 0x80108874
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80108D6C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeViewfinder_copyToCurrent(undefined2* camObj);

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_free
 * EN v1.0 Address: 0x80108914
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80108E08
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Rcp_SetViewFinderHudEnabled(int on);

void CameraModeViewfinder_free(int camObj);

extern void buttonDisable(int port, int mask);
extern void firstPersonZoomOutOnExit(int a, int b);
extern void fn_80137948(char* fmt, ...);
extern char sCam5BYDebugFormat;

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_update
 * EN v1.0 Address: 0x801089D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108EC8
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeViewfinder_update(s16* obj);

extern u32 GameBit_Get(int bit);
extern void* memset(void* dst, int v, int n);
extern f32 lbl_803E1834;

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_init
 * EN v1.0 Address: 0x801089D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109474
 * EN v1.1 Size: 1396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeViewfinder_init(s16* obj, int mode, int* args);


/*
 * --INFO--
 *
 * Function: CameraModeDebug_update
 * EN v1.0 Address: 0x80108A04
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x80109A14
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeDebug_update(short* camObj)
{
    u8* cam = (u8*)camObj;
    u8* state = *(u8**)(cam + 164);
    u16 held;
    f32 move;
    f32 absMove;
    f32 absVel;
    f32 factor;
    f32 radius;

    if ((getButtonsJustPressed(0) & 2) != 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
        return;
    }
    move = lbl_803E1840;
    held = getButtonsHeld(0);
    if ((held & 8) != 0)
    {
        move = lbl_803E1844 * lbl_803DD550->orbitRadius;
    }
    if ((held & 4) != 0)
    {
        move = lbl_803E1848 * lbl_803DD550->orbitRadius;
    }
    absMove = (move < lbl_803E1840) ? -move : move;
    absVel = (lbl_803DD550->radiusVelocity < lbl_803E1840)
                 ? -lbl_803DD550->radiusVelocity
                 : lbl_803DD550->radiusVelocity;
    factor = lbl_803E1850;
    if (absMove < absVel)
    {
        factor = lbl_803E184C;
    }
    lbl_803DD550->radiusVelocity = factor * (move - lbl_803DD550->radiusVelocity) + lbl_803DD550->radiusVelocity;
    lbl_803DD550->orbitRadius = lbl_803DD550->orbitRadius + lbl_803DD550->radiusVelocity;
    if (lbl_803DD550->orbitRadius < lbl_803E1854)
    {
        lbl_803DD550->orbitRadius = lbl_803E1854;
    }
    if (lbl_803DD550->orbitRadius > lbl_803E1858)
    {
        lbl_803DD550->orbitRadius = lbl_803E1858;
    }
    *(s16*)cam = (s16)(*(s16*)cam - (s8)padGetCX(0) * 3);
    *(s16*)(cam + 2) = (s16)(*(s16*)(cam + 2) + (s8)padGetCY(0) * 3);
    {
        f32 cosYaw = mathSinf(lbl_803E185C * (f32)(s32)(*(s16*)cam - 0x4000) / lbl_803E1860);
        f32 sinYaw = mathCosf(lbl_803E185C * (f32)(s32)(*(s16*)cam - 0x4000) / lbl_803E1860);
        f32 sinPitch = mathCosf(lbl_803E185C * (f32)(s32)(*(s16*)(cam + 2) - 0x4000) / lbl_803E1860);
        f32 cosPitch = mathSinf(lbl_803E185C * (f32)(s32)(*(s16*)(cam + 2) - 0x4000) / lbl_803E1860);
        radius = lbl_803DD550->orbitRadius;
        *(f32*)(cam + 24) = *(f32*)(state + 24) + radius * sinPitch * sinYaw;
        *(f32*)(cam + 28) = lbl_803E1854 + *(f32*)(state + 28) + radius * cosPitch;
        *(f32*)(cam + 32) = *(f32*)(state + 32) + radius * sinPitch * cosYaw;
    }
    Obj_TransformWorldPointToLocal(*(f32*)(cam + 24), *(f32*)(cam + 28), *(f32*)(cam + 32),
                                   (f32*)(cam + 12), (f32*)(cam + 16), (f32*)(cam + 20),
                                   *(int*)(cam + 48));
}

/*
 * --INFO--
 *
 * Function: CameraModeDebug_init
 * EN v1.0 Address: 0x80108D54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109D44
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeDebug_init(void)
{
    if (lbl_803DD550 == NULL)
    {
        lbl_803DD550 = (CameraModeDebugState*)mmAlloc(sizeof(CameraModeDebugState), 0xf, 0);
    }
    lbl_803DD550->orbitRadius = lbl_803E1870;
    lbl_803DD550->radiusVelocity = lbl_803E1840;
    return;
}

/*
 * --INFO--
 *
 * Function: fn_80109B04
 * EN v1.0 Address: 0x80108D58
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80109DA0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void* fn_80109B04(f32 x, f32 y, f32 z, int filter1, int filter2);
#pragma dont_inline reset


/*
 * --INFO--
 *
 * Function: CameraModeStatic_update
 * EN v1.0 Address: 0x80108EA8
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80109EE0
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeStatic_update(short* camObj);

/*
 * --INFO--
 *
 * Function: CameraModeStatic_init
 * EN v1.0 Address: 0x80109108
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A198
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeStatic_init(u8* cam, int p2, int* p3);


/*
 * --INFO--
 *
 * Function: fn_8010A104
 * EN v1.0 Address: 0x8010910C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A3A0
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8010A104(int* p1, int* p2, f32 x, f32 y, f32 z, int tag);

/*
 * --INFO--
 *
 * Function: fn_8010A47C
 * EN v1.0 Address: 0x80109110
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x8010A718
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_8010A47C(int curve, int* count, int tag);


/* Trivial 4b 0-arg blr leaves. */
void CameraModeViewfinder_release(void);

void CameraModeViewfinder_initialise(void);

void CameraModeDebug_copyToCurrent_nop(void)
{
}

void CameraModeDebug_release_nop(void)
{
}

void CameraModeDebug_initialise_nop(void)
{
}

void CameraModeStatic_copyToCurrent_nop(void);

void CameraModeStatic_release(void);

void CameraModeStatic_initialise(void);

/* fn_X(lbl); lbl = 0; */
void CameraModeDebug_free(void)
{
    mm_free(lbl_803DD550);
    lbl_803DD550 = 0;
}

void CameraModeStatic_free(void);
