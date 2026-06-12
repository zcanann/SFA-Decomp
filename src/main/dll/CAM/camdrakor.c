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


void CameraModeCombat_copyToCurrent_nop(void)
{
}

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

void fn_8010BF08(int control, float* outX, float* outY, float* outZ, void* inFloatPtr)
{
    int cameraObj;
    CamPathEntry* paths;
    int settings;
    u8 curIdx;
    float t;
    float lim;

    settings = *(int*)(control + 0x11c);
    cameraObj = *(int*)(control + 0xa4);
    paths = *(CamPathEntry**)(settings + 0x74);
    curIdx = *(u8*)(settings + 0xe4);
    if ((u32)curIdx != (u32)lbl_803DD568->pathBlendTargetIndex)
    {
        lbl_803DD568->pathBlendStartIndex = lbl_803DD568->pathBlendTargetIndex;
        lbl_803DD568->pathBlendWeight = lbl_803E18C0;
    }
    t = lbl_803DD568->pathBlendWeight;
    lim = lbl_803E18C4;
    if (t > lim)
    {
        lbl_803DD568->pathBlendWeight = t - lbl_803E18C8 * timeDelta;
        t = lbl_803DD568->pathBlendWeight;
        if (lbl_803DD568->pathBlendWeight < lim)
        {
            lbl_803DD568->pathBlendWeight = lim;
            lbl_803DD568->pathBlendStartIndex = *(u8*)(settings + 0xe4);
        }
        {
            u8 ci = lbl_803DD568->pathBlendStartIndex;
            u8 ti = *(u8*)(settings + 0xe4);
            float dx = paths[ci].x - paths[ti].x;
            float dy = paths[ci].y - paths[ti].y;
            float dz = paths[ci].z - paths[ti].z;
            float w = lbl_803DD568->pathBlendWeight;
            dx *= w;
            dy *= w;
            dz *= w;
            dx += paths[ti].x;
            dy += paths[ti].y;
            dz += paths[ti].z;
            *outX = dx - *(float*)(cameraObj + 0x18);
            *outY = dy - *(float*)inFloatPtr;
            *outZ = dz - *(float*)(cameraObj + 0x20);
        }
    }
    else
    {
        *outX = paths[*(u8*)(settings + 0xe4)].x - *(float*)(cameraObj + 0x18);
        *outY = paths[*(u8*)(settings + 0xe4)].y - *(float*)inFloatPtr;
        *outZ = paths[*(u8*)(settings + 0xe4)].z - *(float*)(cameraObj + 0x20);
    }
    lbl_803DD568->pathBlendTargetIndex = *(u8*)(settings + 0xe4);
}

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

void CameraModeCombat_free(int obj)
{
    if (*(void**)(obj + 0x11c) != NULL)
    {
        (*gCameraInterface)->setTarget(0);
    }
    mm_free(lbl_803DD568);
    lbl_803DD568 = 0;
    Rcp_DisableBlurFilter();
    ((CamByte143*)(obj + 0x143))->flag80 = 0;
}

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
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 FUN_80053bb0();
extern void camcontrol_traceMove(f32 radius, f32* from, void* to, f32* out, void* work, int a,
                                 int b, int c);
extern uint FUN_801ef1a4();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern undefined4 Camera_GetCurrentViewSlot();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293130();
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern uint fn_8029630C(int obj);
extern int objAnimFn_80296328(int obj);
extern undefined4 cameraGetPrevPos2();

extern s32 lbl_803DD56C;
extern CameraModeShipBattleState* lbl_803DD570;
extern CameraModeClimbState* lbl_803DD578;
extern f64 lbl_803E1918;
extern f64 lbl_803E1938;
extern f64 lbl_803E1988;
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

void CameraModeCombat_update(short* cam)
{
    extern void fn_8010BF08(int cam, f32* dx, f32* dy, f32* dz, f32* ty); /* #57 */
    f32 nz;
    f32 ny;
    f32 nx;
    f32 prevZ;
    f32 prevY;
    f32 prevX;
    f32 dy;
    f32 ty;
    f32 dx;
    f32 dz;
    f32 vec[3];
    u8 trace[116];
    int view = (int)Camera_GetCurrentViewSlot();
    char* tgt;
    int focus;
    CombatPathPoint* path;
    f32 range;
    f32 dist;
    f32 px;
    f32 py;
    f32 pz;
    f32 step;
    f32 zoom;
    f32 mag;
    f32 speed;
    f32 lim;
    f32 c;
    f32 sn;
    f32 t;
    f32 fa;
    f32 fb;
    int ang;
    int diff;
    int abs2;
    uint ad;
    short classId;

    if (lbl_803DD568->invalidTarget != 0)
    {
        if (((CameraObject*)cam)->targetObj != NULL)
        {
            if ((*(u8*)(*(int*)&((CameraObject*)cam)->targetObj + 0xaf) & 0x40) || (((CameraObject*)cam)->unk141 & 2))
            {
                return;
            }
            (*gCameraInterface)->setTarget(0);
        }
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
    }
    else
    {
        focus = *(int*)&((CameraObject*)cam)->anim.targetObj;
        if (((GameObject*)focus)->anim.classId == 1 && objAnimFn_80296328(focus) == 0)
        {
            if (((CameraObject*)cam)->targetObj != NULL)
            {
                if ((*(u8*)(*(int*)&((CameraObject*)cam)->targetObj + 0xaf) & 0x40) || (((CameraObject*)cam)->unk141 &
                    2))
                {
                    return;
                }
                (*gCameraInterface)->setTarget(0);
            }
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
        }
        else
        {
            tgt = *(char**)&((CameraObject*)cam)->targetObj;
            if (tgt == NULL || (((GameObject*)tgt)->objectFlags & 0x40) || (*(u8*)&((GameObject*)tgt)->anim.
                resetHitboxMode & 0x28))
            {
                if (tgt != NULL)
                {
                    if ((*(u8*)&((GameObject*)tgt)->anim.resetHitboxMode & 0x40) || (((CameraObject*)cam)->unk141 & 2))
                    {
                        return;
                    }
                    (*gCameraInterface)->setTarget(0);
                }
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            }
            else
            {
                path = *(CombatPathPoint**)(tgt + 0x74);
                if (path != NULL)
                {
                    range = (f32)(s32)(
                        (u32) * (u8*)(*(int*)(*(int*)&((GameObject*)tgt)->anim.modelInstance + 0x40) + 0xd) << 2);
                    if (((u16)getButtonsJustPressed(0) & 0x200) && (int)fn_8029630C(focus) != 0)
                    {
                        if (((CameraObject*)cam)->targetObj != NULL)
                        {
                            if ((*(u8*)(*(int*)&((CameraObject*)cam)->targetObj + 0xaf) & 0x40) || (((CameraObject*)cam)
                                ->unk141 & 2))
                            {
                                return;
                            }
                            (*gCameraInterface)->setTarget(0);
                        }
                        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                    }
                    else
                    {
                        ty = lbl_803E18D0 + ((GameObject*)focus)->anim.worldPosY;
                        classId = ((GameObject*)tgt)->anim.classId;
                        if (classId == 0x1c || classId == 0x6d || classId == 0x2a)
                        {
                            if (((GameObject*)tgt)->anim.seqId == 0x200)
                            {
                                ty = ty + lbl_803E18D0;
                            }
                            if (*(u8*)(*(int*)&((GameObject*)tgt)->anim.modelInstance + 0x72) <= 1)
                            {
                                dx = path[((GameObject*)tgt)->unkE4].x - ((GameObject*)focus)->anim.worldPosX;
                                dy = path[((GameObject*)tgt)->unkE4].y - ty;
                                dz = path[((GameObject*)tgt)->unkE4].z - ((GameObject*)focus)->anim.worldPosZ;
                            }
                            else
                            {
                                fn_8010BF08((int)cam, &dx, &dy, &dz, &ty);
                            }
                        }
                        else
                        {
                            ty = lbl_803E18D0 + ((GameObject*)focus)->anim.worldPosY;
                            dx = path[((GameObject*)tgt)->unkE4].x - ((GameObject*)focus)->anim.worldPosX;
                            dy = path[((GameObject*)tgt)->unkE4].y - ty;
                            dz = path[((GameObject*)tgt)->unkE4].z - ((GameObject*)focus)->anim.worldPosZ;
                        }
                        dist = sqrtf(dx * dx + dz * dz);
                        ((CameraObject*)cam)->unk13B = 0x30;
                        ((CameraObject*)cam)->unk13C = 1;
                        if (dist > range)
                        {
                            if (((CameraObject*)cam)->targetObj != NULL)
                            {
                                if ((*(u8*)(*(int*)&((CameraObject*)cam)->targetObj + 0xaf) & 0x40) || (((CameraObject*)
                                    cam)->unk141 & 2))
                                {
                                    return;
                                }
                                (*gCameraInterface)->setTarget(0);
                            }
                            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                        }
                        else
                        {
                            cameraGetPrevPos2(focus, &prevX, &prevY, &prevZ);
                            px = lbl_803E18D4 * dx + ((GameObject*)focus)->anim.worldPosX;
                            py = lbl_803E18D8 + ty;
                            pz = lbl_803E18D4 * dz + ((GameObject*)focus)->anim.worldPosZ;
                            ang = getAngle(dx, dz);
                            diff = (int)*cam - (0x8000 - ((ang & 0xffff) + 0x8000) & 0xffff);
                            if (diff > 0x8000)
                            {
                                diff = diff - 0xffff;
                            }
                            if (diff < -0x8000)
                            {
                                diff = diff + 0xffff;
                            }
                            if (diff > 9000)
                            {
                                step = interpolate((f32)(s32)(diff - 9000), lbl_803E18DC, timeDelta);
                                *cam = (int)((f32)(s32) * cam - step);
                            }
                            else if (diff < -9000)
                            {
                                step = interpolate((f32)(s32)(diff + 9000), lbl_803E18DC, timeDelta);
                                *cam = (int)((f32)(s32) * cam - step);
                            }
                            if (diff < 3000 && diff > 0)
                            {
                                if (lbl_803DD56C < 3000 && diff < 1000 && diff < lbl_803DD56C)
                                {
                                    step = interpolate((f32)(s32)(-diff - 3000), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32) * cam + step);
                                }
                                else
                                {
                                    step = interpolate((f32)(s32)(3000 - diff), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32) * cam + step);
                                }
                            }
                            else if (diff > -3000 && diff < 0)
                            {
                                if (lbl_803DD56C < -2999 || diff < -999 || diff <= lbl_803DD56C)
                                {
                                    step = interpolate((f32)(s32)(-diff - 3000), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32) * cam + step);
                                }
                                else
                                {
                                    step = interpolate((f32)(s32)(3000 - diff), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32) * cam + step);
                                }
                            }
                            abs2 = diff;
                            if (diff < 0)
                            {
                                abs2 = -diff;
                            }
                            if (abs2 > 9000)
                            {
                                abs2 = 9000;
                            }
                            zoom = (f32)(s32)(9000 - abs2) / lbl_803E18E4;
                            lbl_803DD56C = diff;
                            step = interpolate(lbl_803E18E8 - lbl_803DD568->heightOffset, lbl_803E18EC, timeDelta);
                            lbl_803DD568->heightOffset = lbl_803DD568->heightOffset + step;
                            step = interpolate(
                                (lbl_803E18F0 + (lbl_803E18C0 - zoom)) / lbl_803E18F4 - lbl_803DD568->zoomOffset,
                                lbl_803E18F8, timeDelta);
                            lbl_803DD568->zoomOffset = lbl_803DD568->zoomOffset + step;
                            c = mathSinf((lbl_803E18FC * (f32)(s32) * cam) / lbl_803E1900);
                            sn = mathCosf((lbl_803E18FC * (f32)(s32) * cam) / lbl_803E1900);
                            t = lbl_803DD568->followDistance * c;
                            nx = px + t;
                            t = lbl_803DD568->followDistance * sn;
                            nz = pz - t;
                            dy = dy * lbl_803E1904;
                            dy = ty - dy;
                            dy = dy + lbl_803DD568->heightOffset;
                            step = interpolate(((CameraObject*)cam)->anim.worldPosY - dy, lbl_803E1908, timeDelta);
                            ny = ((CameraObject*)cam)->anim.worldPosY - step;
                            PSVECSubtract(&nx, (f32*)((char*)cam + 0x18), vec);
                            mag = PSVECMag(vec);
                            if (lbl_803E18C4 < mag)
                            {
                                PSVECNormalize(vec, vec);
                            }
                            speed = mag;
                            if (((CameraObject*)cam)->unkF4 <= lbl_803E18C4)
                            {
                                fa = ((GameObject*)focus)->anim.previousWorldPosX - ((GameObject*)focus)->anim.
                                    worldPosX;
                                fb = ((GameObject*)focus)->anim.previousWorldPosZ - ((GameObject*)focus)->anim.
                                    worldPosZ;
                                speed = sqrtf(fa * fa + fb * fb);
                                lim = speed * (lbl_803E190C * timeDelta);
                                if ((f64)lim < lbl_803E1918)
                                {
                                    lim = lbl_803E1910;
                                }
                                speed = mag;
                                if (mag < lbl_803E18C4)
                                {
                                    speed = lbl_803E18C4;
                                }
                                else if (mag > lim)
                                {
                                    speed = lim;
                                }
                            }
                            if (speed < lbl_803E18C4)
                            {
                                speed = lbl_803E18C4;
                            }
                            else if (speed > lbl_803E18D0)
                            {
                                speed = lbl_803E18D0;
                            }
                            PSVECScale(vec, vec, speed);
                            PSVECAdd((f32*)((char*)cam + 0x18), vec, (f32*)((char*)cam + 0x18));
                            camcontrol_traceMove(lbl_803E18CC, &prevX, (f32*)((char*)cam + 0x18),
                                                 (f32*)((char*)cam + 0x18), trace, 3, 1, 1);
                            fb = *(f32*)(view + 0xc) - (lbl_803E18F8 * dx + ((GameObject*)focus)->anim.worldPosX);
                            dy = *(f32*)(view + 0x10) - py;
                            fa = *(f32*)(view + 0x14) - (lbl_803E18F8 * dz + ((GameObject*)focus)->anim.worldPosZ);
                            t = sqrtf(fb * fb + fa * fa);
                            ad = getAngle(dy, t);
                            ad = (ad & 0xffff) - ((int)cam[1] & 0xffffU);
                            if ((int)ad > 0x8000)
                            {
                                ad = ad - 0xffff;
                            }
                            if ((int)ad < -0x8000)
                            {
                                ad = ad + 0xffff;
                            }
                            step = interpolate((f32)(s32)ad, lbl_803E1920, timeDelta);
                            cam[1] = (int)
                            ((f32)(s32)
                            cam[1] + step
                            )
                            ;
                            fa = lbl_803E1924 + dist;
                            if (lbl_803E1924 + dist < lbl_803E1928)
                            {
                                fa = lbl_803E1928;
                            }
                            if (lbl_803E192C < fa)
                            {
                                fa = lbl_803E192C;
                            }
                            t = fa - lbl_803DD568->followDistance;
                            step = powfBitEstimate(lbl_803E18EC, timeDelta);
                            fa = t * step;
                            if (fa > lbl_803E18D8 * timeDelta)
                            {
                                fa = lbl_803E18D8 * timeDelta;
                            }
                            else if (fa < lbl_803E1930 * timeDelta)
                            {
                                fa = lbl_803E1930 * timeDelta;
                            }
                            lbl_803DD568->followDistance = lbl_803DD568->followDistance + fa;
                            turnOnBlurFilter(((GameObject*)tgt)->anim.worldPosX, ((GameObject*)tgt)->anim.worldPosY,
                                             ((GameObject*)tgt)->anim.worldPosZ, 1, 0);
                            if (lbl_803E18C4 == ((CameraObject*)cam)->unkF4)
                            {
                                ((CombatCamFlags*)((char*)cam + 0x143))->b80 = 1;
                            }
                            Obj_TransformWorldPointToLocal(*(f32*)((char*)cam + 0x18),
                                                           ((CameraObject*)cam)->anim.worldPosY,
                                                           ((CameraObject*)cam)->anim.worldPosZ,
                                                           &((CameraObject*)cam)->anim.localPosX,
                                                           &((CameraObject*)cam)->anim.localPosY,
                                                           &((CameraObject*)cam)->anim.localPosZ,
                                                           *(int*)&((CameraObject*)cam)->anim.parent);
                        }
                    }
                }
            }
        }
    }
}

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
void CameraModeCombat_init(int camObj, undefined4 arg2, undefined4* args)
{
    float dx;
    float dz;
    int posEntry;
    int targetObj;
    int playerObj;
    double fconv;

    *(undefined4*)(camObj + 0x11c) = *args;
    playerObj = *(int*)(camObj + 0xa4);
    if (lbl_803DD568 == (CameraModeCombatState*)0x0)
    {
        lbl_803DD568 = (CameraModeCombatState*)mmAlloc(0x1c, 0xf, 0);
    }
    dx = lbl_803E18C4;
    lbl_803DD568->heightOffset = lbl_803E18C4;
    lbl_803DD568->zoomOffset = lbl_803E18C0;
    lbl_803DD568->invalidTarget = 0;
    lbl_803DD568->unk11 = 0;
    lbl_803DD568->pathBlendStartIndex = 1;
    lbl_803DD568->pathBlendTargetIndex = 1;
    lbl_803DD568->pathBlendWeight = dx;
    if (*(short*)(playerObj + 0x44) != 1)
    {
        lbl_803DD568->invalidTarget = 1;
    }
    else
    {
        targetObj = *(int*)(camObj + 0x11c);
        if ((void*)targetObj == NULL)
        {
            lbl_803DD568->invalidTarget = 1;
        }
        else
        {
            if (*(void**)(targetObj + 0x74) == NULL)
            {
                dx = *(float*)(playerObj + 0x18) - *(float*)(targetObj + 0x18);
                dz = *(float*)(playerObj + 0x20) - *(float*)(targetObj + 0x20);
            }
            else
            {
                posEntry = *(int*)(targetObj + 0x74) + (uint) * (byte*)(targetObj + 0xe4) * 0x18;
                dx = *(float*)(posEntry + 0xc) - *(float*)(playerObj + 0x18);
                dz = *(float*)(posEntry + 0x14) - *(float*)(playerObj + 0x20);
            }
            if (*(short*)(targetObj + 0x44) != 0x6d)
            {
                lbl_803DD568->followDistance = sqrtf(dx * dx + dz * dz);
            }
            else
            {
                lbl_803DD568->followDistance = lbl_803E1940;
            }
            lbl_803DD568->unk10 = 0;
        }
    }
    return;
}


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
void CameraModeCombat_release(void)
{
}

void CameraModeCombat_initialise(void)
{
}

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
