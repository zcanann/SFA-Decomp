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


extern u32 getButtonsHeld(int port);
extern char padGetCX(int port);
extern char padGetCY(int port);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern CameraModeDebugState* lbl_803DD550;
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


/* Trivial 4b 0-arg blr leaves. */


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


/* fn_X(lbl); lbl = 0; */
void CameraModeDebug_free(void)
{
    mm_free(lbl_803DD550);
    lbl_803DD550 = 0;
}

void CameraModeStatic_free(void);
