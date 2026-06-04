#include "ghidra_import.h"
#include "main/dll/CAM/camdrakor.h"
#include "main/dll/CAM/dll_60.h"


#pragma peephole off
#pragma scheduling off
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                           int obj);
extern void* FUN_800069a8();
extern uint getButtonsJustPressed();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 FUN_80053bb0();
extern void *mmAlloc(int size,int heap,int flags);
extern void camcontrol_traceMove(f32 radius, f32 *from, void *to, f32 *out, void *work, int a,
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
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern uint fn_8029630C(int obj);
extern int objAnimFn_80296328(int obj);
extern undefined4 cameraGetPrevPos2();

extern undefined4* gCameraInterface;
extern f32* lbl_803DD568;
extern s32 lbl_803DD56C;
extern f32* lbl_803DD570;
extern void* lbl_803DD578;
extern f64 lbl_803E1918;
extern f64 lbl_803E1938;
extern f64 lbl_803E1988;
extern f32 timeDelta;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
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
typedef struct {
    f32 pad0;
    f32 pad4;
    f32 pad8;
    f32 x;
    f32 y;
    f32 z;
} CombatPathPoint;

typedef struct {
    u8 b80 : 1;
    u8 rest : 7;
} CombatCamFlags;

extern int getAngle(f32 dx, f32 dz);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern f32 powfBitEstimate(f32 a, f32 b);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern f32 PSVECMag(f32 *v);
extern void PSVECNormalize(f32 *v, f32 *out);
extern void PSVECScale(f32 *v, f32 *out, f32 s);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern void turnOnBlurFilter(f32 x, f32 y, f32 z, int a, int b);
extern void fn_8010BF08(int cam, f32 *dx, f32 *dy, f32 *dz, f32 *ty);

void CameraModeCombat_update(short *cam)
{
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
    char *tgt;
    int focus;
    CombatPathPoint *path;
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
    f32 fVar1;
    f32 fVar3;
    int ang;
    int diff;
    int abs2;
    uint ad;
    short sVar2;

    if (*(u8 *)((int)lbl_803DD568 + 0x12) != 0) {
        if (*(void **)((char *)cam + 0x11c) != NULL) {
            if ((*(u8 *)(*(int *)((char *)cam + 0x11c) + 0xaf) & 0x40) || (*(u8 *)((char *)cam + 0x141) & 2)) {
                return;
            }
            (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
        }
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(0x42, 0, 1, 0, 0, 0x1e, 0xff);
    } else {
        focus = *(int *)((char *)cam + 0xa4);
        if (*(s16 *)(focus + 0x44) == 1 && objAnimFn_80296328(focus) == 0) {
            if (*(void **)((char *)cam + 0x11c) != NULL) {
                if ((*(u8 *)(*(int *)((char *)cam + 0x11c) + 0xaf) & 0x40) || (*(u8 *)((char *)cam + 0x141) & 2)) {
                    return;
                }
                (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
            }
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(0x42, 0, 1, 0, 0, 0x1e, 0xff);
        } else {
            tgt = *(char **)((char *)cam + 0x11c);
            if (tgt == NULL || (*(u16 *)(tgt + 0xb0) & 0x40) || (*(u8 *)(tgt + 0xaf) & 0x28)) {
                if (tgt != NULL) {
                    if ((*(u8 *)(tgt + 0xaf) & 0x40) || (*(u8 *)((char *)cam + 0x141) & 2)) {
                        return;
                    }
                    (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
                }
                (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(0x42, 0, 1, 0, 0, 0x1e, 0xff);
            } else {
                path = *(CombatPathPoint **)(tgt + 0x74);
                if (path != NULL) {
                    range = (f32)(s32)((u32)*(u8 *)(*(int *)(*(int *)(tgt + 0x50) + 0x40) + 0xd) << 2);
                    if (((u16)getButtonsJustPressed(0) & 0x200) && (int)fn_8029630C(focus) != 0) {
                        if (*(void **)((char *)cam + 0x11c) != NULL) {
                            if ((*(u8 *)(*(int *)((char *)cam + 0x11c) + 0xaf) & 0x40) || (*(u8 *)((char *)cam + 0x141) & 2)) {
                                return;
                            }
                            (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
                        }
                        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(0x42, 0, 1, 0, 0, 0x1e, 0xff);
                    } else {
                        ty = lbl_803E18D0 + *(f32 *)(focus + 0x1c);
                        sVar2 = *(s16 *)(tgt + 0x44);
                        if (sVar2 == 0x1c || sVar2 == 0x6d || sVar2 == 0x2a) {
                            if (*(s16 *)(tgt + 0x46) == 0x200) {
                                ty = ty + lbl_803E18D0;
                            }
                            if (*(u8 *)(*(int *)(tgt + 0x50) + 0x72) <= 1) {
                                dx = path[*(u8 *)(tgt + 0xe4)].x - *(f32 *)(focus + 0x18);
                                dy = path[*(u8 *)(tgt + 0xe4)].y - ty;
                                dz = path[*(u8 *)(tgt + 0xe4)].z - *(f32 *)(focus + 0x20);
                            } else {
                                fn_8010BF08((int)cam, &dx, &dy, &dz, &ty);
                            }
                        } else {
                            ty = lbl_803E18D0 + *(f32 *)(focus + 0x1c);
                            dx = path[*(u8 *)(tgt + 0xe4)].x - *(f32 *)(focus + 0x18);
                            dy = path[*(u8 *)(tgt + 0xe4)].y - ty;
                            dz = path[*(u8 *)(tgt + 0xe4)].z - *(f32 *)(focus + 0x20);
                        }
                        dist = sqrtf(dx * dx + dz * dz);
                        *(u8 *)((char *)cam + 0x13b) = 0x30;
                        *(u8 *)((char *)cam + 0x13c) = 1;
                        if (dist > range) {
                            if (*(void **)((char *)cam + 0x11c) != NULL) {
                                if ((*(u8 *)(*(int *)((char *)cam + 0x11c) + 0xaf) & 0x40) || (*(u8 *)((char *)cam + 0x141) & 2)) {
                                    return;
                                }
                                (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
                            }
                            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(0x42, 0, 1, 0, 0, 0x1e, 0xff);
                        } else {
                            cameraGetPrevPos2(focus, &prevX, &prevY, &prevZ);
                            px = lbl_803E18D4 * dx + *(f32 *)(focus + 0x18);
                            py = lbl_803E18D8 + ty;
                            pz = lbl_803E18D4 * dz + *(f32 *)(focus + 0x20);
                            ang = getAngle(dx, dz);
                            diff = (int)*cam - (0x8000 - ((ang & 0xffff) + 0x8000) & 0xffff);
                            if (diff > 0x8000) {
                                diff = diff - 0xffff;
                            }
                            if (diff < -0x8000) {
                                diff = diff + 0xffff;
                            }
                            if (diff > 9000) {
                                step = interpolate((f32)(s32)(diff - 9000), lbl_803E18DC, timeDelta);
                                *cam = (int)((f32)(s32)*cam - step);
                            } else if (diff < -9000) {
                                step = interpolate((f32)(s32)(diff + 9000), lbl_803E18DC, timeDelta);
                                *cam = (int)((f32)(s32)*cam - step);
                            }
                            if (diff < 3000 && diff > 0) {
                                if (lbl_803DD56C < 3000 && diff < 1000 && diff < lbl_803DD56C) {
                                    step = interpolate((f32)(s32)(-diff - 3000), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32)*cam + step);
                                } else {
                                    step = interpolate((f32)(s32)(3000 - diff), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32)*cam + step);
                                }
                            } else if (diff > -3000 && diff < 0) {
                                if (lbl_803DD56C < -2999 || diff < -999 || diff <= lbl_803DD56C) {
                                    step = interpolate((f32)(s32)(-diff - 3000), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32)*cam + step);
                                } else {
                                    step = interpolate((f32)(s32)(3000 - diff), lbl_803E18E0, timeDelta);
                                    *cam = (int)((f32)(s32)*cam + step);
                                }
                            }
                            abs2 = diff;
                            if (diff < 0) {
                                abs2 = -diff;
                            }
                            if (abs2 > 9000) {
                                abs2 = 9000;
                            }
                            zoom = (f32)(s32)(9000 - abs2) / lbl_803E18E4;
                            lbl_803DD56C = diff;
                            step = interpolate(lbl_803E18E8 - lbl_803DD568[1], lbl_803E18EC, timeDelta);
                            lbl_803DD568[1] = lbl_803DD568[1] + step;
                            step = interpolate((lbl_803E18F0 + (lbl_803E18C0 - zoom)) / lbl_803E18F4 - lbl_803DD568[2], lbl_803E18F8, timeDelta);
                            lbl_803DD568[2] = lbl_803DD568[2] + step;
                            c = fn_80293E80((lbl_803E18FC * (f32)(s32)*cam) / lbl_803E1900);
                            sn = sin((lbl_803E18FC * (f32)(s32)*cam) / lbl_803E1900);
                            t = lbl_803DD568[0] * c;
                            nx = px + t;
                            t = lbl_803DD568[0] * sn;
                            nz = pz - t;
                            dy = dy * lbl_803E1904;
                            dy = ty - dy;
                            dy = dy + lbl_803DD568[1];
                            step = interpolate(*(f32 *)((char *)cam + 0x1c) - dy, lbl_803E1908, timeDelta);
                            ny = *(f32 *)((char *)cam + 0x1c) - step;
                            PSVECSubtract(&nx, (f32 *)((char *)cam + 0x18), vec);
                            mag = PSVECMag(vec);
                            if (lbl_803E18C4 < mag) {
                                PSVECNormalize(vec, vec);
                            }
                            speed = mag;
                            if (*(f32 *)((char *)cam + 0xf4) <= lbl_803E18C4) {
                                fVar1 = *(f32 *)(focus + 0x8c) - *(f32 *)(focus + 0x18);
                                fVar3 = *(f32 *)(focus + 0x94) - *(f32 *)(focus + 0x20);
                                speed = sqrtf(fVar1 * fVar1 + fVar3 * fVar3);
                                lim = speed * (lbl_803E190C * timeDelta);
                                if ((f64)lim < lbl_803E1918) {
                                    lim = lbl_803E1910;
                                }
                                speed = mag;
                                if (mag < lbl_803E18C4) {
                                    speed = lbl_803E18C4;
                                } else if (mag > lim) {
                                    speed = lim;
                                }
                            }
                            if (speed < lbl_803E18C4) {
                                speed = lbl_803E18C4;
                            } else if (speed > lbl_803E18D0) {
                                speed = lbl_803E18D0;
                            }
                            PSVECScale(vec, vec, speed);
                            PSVECAdd((f32 *)((char *)cam + 0x18), vec, (f32 *)((char *)cam + 0x18));
                            camcontrol_traceMove(lbl_803E18CC, &prevX, (f32 *)((char *)cam + 0x18), (f32 *)((char *)cam + 0x18), trace, 3, 1, 1);
                            fVar3 = *(f32 *)(view + 0xc) - (lbl_803E18F8 * dx + *(f32 *)(focus + 0x18));
                            dy = *(f32 *)(view + 0x10) - py;
                            fVar1 = *(f32 *)(view + 0x14) - (lbl_803E18F8 * dz + *(f32 *)(focus + 0x20));
                            t = sqrtf(fVar3 * fVar3 + fVar1 * fVar1);
                            ad = getAngle(dy, t);
                            ad = (ad & 0xffff) - ((int)cam[1] & 0xffffU);
                            if ((int)ad > 0x8000) {
                                ad = ad - 0xffff;
                            }
                            if ((int)ad < -0x8000) {
                                ad = ad + 0xffff;
                            }
                            step = interpolate((f32)(s32)ad, lbl_803E1920, timeDelta);
                            cam[1] = (int)((f32)(s32)cam[1] + step);
                            fVar1 = lbl_803E1924 + dist;
                            if (lbl_803E1924 + dist < lbl_803E1928) {
                                fVar1 = lbl_803E1928;
                            }
                            if (lbl_803E192C < fVar1) {
                                fVar1 = lbl_803E192C;
                            }
                            t = fVar1 - lbl_803DD568[0];
                            step = powfBitEstimate(lbl_803E18EC, timeDelta);
                            fVar1 = t * step;
                            if (fVar1 > lbl_803E18D8 * timeDelta) {
                                fVar1 = lbl_803E18D8 * timeDelta;
                            } else if (fVar1 < lbl_803E1930 * timeDelta) {
                                fVar1 = lbl_803E1930 * timeDelta;
                            }
                            lbl_803DD568[0] = lbl_803DD568[0] + fVar1;
                            turnOnBlurFilter(*(f32 *)(tgt + 0x18), *(f32 *)(tgt + 0x1c), *(f32 *)(tgt + 0x20), 1, 0);
                            if (lbl_803E18C4 == *(f32 *)((char *)cam + 0xf4)) {
                                ((CombatCamFlags *)((char *)cam + 0x143))->b80 = 1;
                            }
                            Obj_TransformWorldPointToLocal(*(f32 *)((char *)cam + 0x18), *(f32 *)((char *)cam + 0x1c), *(f32 *)((char *)cam + 0x20),
                                                           (f32 *)((char *)cam + 0xc), (f32 *)((char *)cam + 0x10), (f32 *)((char *)cam + 0x14),
                                                           *(int *)((char *)cam + 0x30));
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
void CameraModeCombat_init(int param_1,undefined4 param_2,undefined4 *param_3)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;

  *(undefined4 *)(param_1 + 0x11c) = *param_3;
  iVar5 = *(int *)(param_1 + 0xa4);
  if (lbl_803DD568 == (float *)0x0) {
    lbl_803DD568 = (float *)mmAlloc(0x1c,0xf,0);
  }
  fVar1 = lbl_803E18C4;
  lbl_803DD568[1] = lbl_803E18C4;
  lbl_803DD568[2] = lbl_803E18C0;
  *(undefined *)((int)lbl_803DD568 + 0x12) = 0;
  *(undefined *)((int)lbl_803DD568 + 0x11) = 0;
  *(undefined *)((int)lbl_803DD568 + 0x13) = 1;
  *(undefined *)(lbl_803DD568 + 5) = 1;
  lbl_803DD568[6] = fVar1;
  if (*(short *)(iVar5 + 0x44) == 1) {
    iVar4 = *(int *)(param_1 + 0x11c);
    if ((void *)iVar4 == NULL) {
      *(undefined *)((int)lbl_803DD568 + 0x12) = 1;
    }
    else {
      if (*(void **)(iVar4 + 0x74) == NULL) {
        fVar1 = *(float *)(iVar5 + 0x18) - *(float *)(iVar4 + 0x18);
        fVar2 = *(float *)(iVar5 + 0x20) - *(float *)(iVar4 + 0x20);
      }
      else {
        iVar3 = *(int *)(iVar4 + 0x74) + (uint)*(byte *)(iVar4 + 0xe4) * 0x18;
        fVar1 = *(float *)(iVar3 + 0xc) - *(float *)(iVar5 + 0x18);
        fVar2 = *(float *)(iVar3 + 0x14) - *(float *)(iVar5 + 0x20);
      }
      if (*(short *)(iVar4 + 0x44) == 0x6d) {
        *lbl_803DD568 = lbl_803E1940;
      }
      else {
        dVar6 = (double)sqrtf(fVar1 * fVar1 + fVar2 * fVar2);
        *lbl_803DD568 = (float)dVar6;
      }
      *(undefined *)(lbl_803DD568 + 4) = 0;
    }
  }
  else {
    *(undefined *)((int)lbl_803DD568 + 0x12) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010cdf4
 * EN v1.0 Address: 0x8010CDF4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010D160
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010cdf4(void)
{
  FUN_80017814(lbl_803DD570);
  lbl_803DD570 = 0;
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
void CameraModeShipBattle_update(undefined2 *param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  uint uVar5;
  int iVar6;
  
  uVar5 = 0;
  iVar6 = *(int *)(param_1 + 0x52);
  if (iVar6 != 0) {
    uVar5 = FUN_801ef1a4(iVar6);
  }
  if (uVar5 != *(byte *)(lbl_803DD570 + 10)) {
    fVar3 = lbl_803E1948;
    if ((uVar5 == 2) ||
       (fVar1 = lbl_803E1950, fVar2 = lbl_803E1954, fVar3 = lbl_803E194C, uVar5 == 5)) {
      fVar1 = lbl_803E1958;
      fVar2 = lbl_803DD570[1];
    }
    *(char *)(lbl_803DD570 + 10) = (char)uVar5;
    lbl_803DD570[6] = fVar3 - lbl_803DD570[3];
    lbl_803DD570[4] = lbl_803DD570[3];
    lbl_803DD570[9] = fVar1 - (lbl_803DD570[7] + fVar2);
    lbl_803DD570[8] = lbl_803DD570[7];
    lbl_803DD570[5] = lbl_803E1954;
  }
  fVar3 = lbl_803E195C;
  if (lbl_803DD570[5] < lbl_803E195C) {
    lbl_803DD570[5] = lbl_803E1960 * timeDelta + lbl_803DD570[5];
    if (fVar3 < lbl_803DD570[5]) {
      lbl_803DD570[5] = fVar3;
    }
    lbl_803DD570[3] = lbl_803DD570[5] * lbl_803DD570[6] + lbl_803DD570[4];
    lbl_803DD570[7] = lbl_803DD570[5] * lbl_803DD570[9] + lbl_803DD570[8];
  }
  dVar4 = lbl_803E1988;
  if ((uVar5 == 2) || (uVar5 == 5)) {
    *lbl_803DD570 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   lbl_803E1988) / lbl_803E1964) * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           lbl_803E1968) * timeDelta - lbl_803DD570[1]);
    fVar3 = lbl_803E196C;
    *lbl_803DD570 = -(lbl_803E196C * *lbl_803DD570 * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] = -(fVar3 * lbl_803DD570[1] * timeDelta - lbl_803DD570[1]);
    *(float *)(param_1 + 0xe) = lbl_803DD570[1] + *(float *)(iVar6 + 0x1c) + lbl_803DD570[7];
  }
  else {
    *lbl_803DD570 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   lbl_803E1988) / lbl_803E1964) * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           lbl_803E1968) * timeDelta - lbl_803DD570[1]);
    fVar3 = lbl_803E196C;
    *lbl_803DD570 = -(lbl_803E196C * *lbl_803DD570 * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] = -(fVar3 * lbl_803DD570[1] * timeDelta - lbl_803DD570[1]);
    *(float *)(param_1 + 0xe) = lbl_803DD570[1] + *(float *)(iVar6 + 0x1c) + lbl_803DD570[7];
  }
  *(float *)(param_1 + 0xc) = lbl_803E1970 + *(float *)(iVar6 + 0x18) + lbl_803DD570[2];
  *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + *lbl_803DD570;
  param_1[1] = 0x708;
  *param_1 = 0x4000;
  param_1[2] = (short)(-(int)*(short *)(iVar6 + 4) >> 3);
  *(float *)(param_1 + 0x5a) = lbl_803E1974;
  fVar3 = (lbl_803DD570[3] - lbl_803DD570[2]) / lbl_803E1978;
  fVar1 = lbl_803E197C;
  if ((fVar3 <= lbl_803E197C) && (fVar1 = fVar3, fVar3 < lbl_803E1980)) {
    fVar1 = lbl_803E1980;
  }
  lbl_803DD570[2] = lbl_803DD570[2] + fVar1 * timeDelta;
  Obj_TransformWorldPointToLocal(*(float *)(param_1 + 0xc),*(float *)(param_1 + 0xe),
               *(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
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
#pragma scheduling off
void CameraModeShipBattle_init(void)
{
  float fVar1;
  u8 zero;

  if (lbl_803DD570 == (float *)0x0) {
    lbl_803DD570 = (float *)mmAlloc(0x2c,0xf,0);
  }
  fVar1 = lbl_803E1954;
  *lbl_803DD570 = lbl_803E1954;
  lbl_803DD570[1] = fVar1;
  lbl_803DD570[2] = lbl_803E1978;
  fVar1 = lbl_803E194C;
  lbl_803DD570[4] = lbl_803E194C;
  lbl_803DD570[3] = fVar1;
  lbl_803DD570[5] = lbl_803E195C;
  zero = 0;
  *(u8 *)(lbl_803DD570 + 10) = zero;
  fVar1 = lbl_803E1950;
  lbl_803DD570[8] = lbl_803E1950;
  lbl_803DD570[7] = fVar1;
  return;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8010d450
 * EN v1.0 Address: 0x8010D450
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010D5DC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010d450(void)
{
  FUN_80017814(lbl_803DD578);
  lbl_803DD578 = 0;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeCombat_release(void) {}
void CameraModeCombat_initialise(void) {}
void CameraModeShipBattle_copyToCurrent_nop(void) {}
void CameraModeShipBattle_release(void) {}
void CameraModeShipBattle_initialise(void) {}
void CameraModeClimb_copyToCurrent_nop(void) {}

/* fn_X(lbl); lbl = 0; */
extern void mm_free(void *);
#pragma scheduling off
#pragma peephole off
void CameraModeShipBattle_free(void) { mm_free(lbl_803DD570); lbl_803DD570 = 0; }
void CameraModeClimb_free(void) { mm_free(lbl_803DD578); lbl_803DD578 = 0; }
#pragma peephole reset
#pragma scheduling reset
