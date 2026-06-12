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
void CameraModeDebug_update(short* camObj);

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
void CameraModeDebug_init(void);

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
void fn_8010A104(int* p1, int* p2, f32 x, f32 y, f32 z, int tag)
{
    int curve;
    int linked;
    int i;
    int k;
    int window[4];
    int count;
    int dummy;
    int found;
    int done;
    f32 dist;

    curve = (int)(*gRomCurveInterface)->getById(*p1);
    found = 1;
    for (i = 0; i < 5; i++)
    {
        if (*(int*)(curve + 28 + i * 4) > -1 &&
            ((s8) * (s8*)(curve + 27) & (1 << i)) == 0)
        {
            linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + 28 + i * 4));
            if (linked != 0 &&
                (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                    *(u8*)(linked + 51) == tag))
            {
                found = 0;
                i = 5;
            }
        }
    }
    if (found != 0)
    {
        for (i = 0; i < 5; i++)
        {
            if (*(int*)(curve + 28 + i * 4) > -1 &&
                ((s8) * (s8*)(curve + 27) & (1 << i)) != 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + 28 + i * 4));
                if (linked != 0 &&
                    (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                        *(u8*)(linked + 51) == tag))
                {
                    *p1 = *(int*)(curve + 28 + i * 4);
                    i = 5;
                }
            }
        }
    }
    done = 0;
    do
    {
        done = 1;
        curve = (int)(*gRomCurveInterface)->getById(*p1);
        pathcam_findTaggedNodeWindow((u8*)curve, window, tag);
        dist = fn_8010AC48(window, x, y, z);
        if (dist < lbl_803E1888)
        {
            if (window[0] > -1)
            {
                *p1 = window[0];
                done = 0;
            }
        }
        else if (dist > lbl_803E188C)
        {
            if (window[2] > -1 && window[3] > -1)
            {
                *p1 = window[2];
                done = 0;
            }
        }
    }
    while (done == 0);
    curve = (int)(*gRomCurveInterface)->getById(*p1);
    fn_8010A47C(curve, &count, tag);
    curve = (int)(*gRomCurveInterface)->getById(*p2);
    *p2 = *(int*)(fn_8010A47C(curve, &dummy, tag) + 20);
    for (k = 0; k < count; k++)
    {
        curve = (int)(*gRomCurveInterface)->getById(*p2);
        for (i = 0; i < 5; i++)
        {
            if (*(int*)(curve + 28 + i * 4) > -1 &&
                ((s8) * (s8*)(curve + 27) & (1 << i)) == 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + 28 + i * 4));
                if (linked != 0 &&
                    (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                        *(u8*)(linked + 51) == tag))
                {
                    *p2 = *(int*)(curve + 28 + i * 4);
                    i = 5;
                }
            }
        }
    }
}

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
int fn_8010A47C(int curve, int* count, int tag)
{
    int i;
    int done;
    int linked;

    done = 0;
    *count = 0;
    while (done == 0)
    {
        done = 1;
        if ((*(char*)(curve + 0x19) != '\x1b') && (*(char*)(curve + 0x19) != '\x1a'))
        {
            for (i = 0; i < 5; i = i + 1)
            {
                if ((*(int*)(curve + i * 4 + 0x1c) > -1) &&
                    (((int)*(char*)(curve + 0x1b) & (1 << i)) != 0))
                {
                    linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + i * 4 + 0x1c));
                    if (((u32)linked != 0) &&
                        ((*(u8*)(linked + 0x31) == tag || (*(u8*)(linked + 0x32) == tag)) ||
                            (*(u8*)(linked + 0x33) == tag)))
                    {
                        curve = linked;
                        done = 0;
                        i = 5;
                    }
                }
            }
        }
        if (done == 0)
        {
            *count = *count + 1;
        }
    }
    return curve;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeViewfinder_release(void);

void CameraModeViewfinder_initialise(void);

void CameraModeDebug_copyToCurrent_nop(void);

void CameraModeDebug_release_nop(void);

void CameraModeDebug_initialise_nop(void);

void CameraModeStatic_copyToCurrent_nop(void);

void CameraModeStatic_release(void);

void CameraModeStatic_initialise(void);

/* fn_X(lbl); lbl = 0; */
void CameraModeDebug_free(void);

void CameraModeStatic_free(void);
