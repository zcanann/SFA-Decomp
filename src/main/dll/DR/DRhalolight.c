#include "ghidra_import.h"
#include "main/dll/DR/DRhalolight.h"

extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017814();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_801e9c00();
extern undefined4 FUN_801ecdec();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern double FUN_80293900();

extern undefined4* DAT_803dd6e8;
extern f32 lbl_803E6784;
extern f32 lbl_803E6828;
extern f32 lbl_803E682C;
extern f32 lbl_803E6830;
extern f32 lbl_803E6840;
extern f32 lbl_803E6850;

/*
 * --INFO--
 *
 * Function: SnowBike_hitDetect
 * EN v1.0 Address: 0x801ECF94
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801ED20C
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void fn_801EB940(int obj, u8 *state);
extern f32 PSVECMag(f32 *v);
extern void doRumble(f32 f);
extern int arrayIndexOf(s16 *arr, int n, int value);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int ch);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void Sfx_SetObjectSfxVolume(int obj, int sfx, u8 vol, f32 v);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 f);
extern void OSReport(char *fmt, ...);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern s16 lbl_8032855C[];
extern char lbl_803DC0E4;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B28;
extern f32 lbl_803E5B88;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5BA4;
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C4C;

typedef struct {
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} HaloSnowBikeFlags;

#pragma scheduling off
#pragma peephole off
void SnowBike_hitDetect(int obj)
{
    u8 *state;
    u8 *other;
    int vol;
    f32 mag;
    f32 k;
    f32 k2;
    f32 v;
    f32 c;
    f32 lim;
    f32 dummy;

    state = *(u8 **)(obj + 0xb8);
    other = *(u8 **)(*(int *)(obj + 0x54));
    if (*(void **)(obj + 0xc0) != NULL) {
        return;
    }
    if (*(s8 *)(state + 0x421) == 2) {
        fn_801EB940(obj, state);
        *(s16 *)(state + 0x41c) = *(s16 *)(obj + 2);
        *(s16 *)(state + 0x41e) = *(s16 *)(obj + 4);
        *(s16 *)(obj + 2) = (f32)*(s16 *)(obj + 2) + *(f32 *)(state + 0x594);
        *(s16 *)(obj + 4) = (f32)*(s16 *)(obj + 4) + ((f32)*(int *)(state + 0x410) + *(f32 *)(state + 0x598));
    }
    if (*(s8 *)(state + 0x3d9) == 4 || state[0x3d6] != 0) {
        *(f32 *)(obj + 0x28) = oneOverTimeDelta * (*(f32 *)(obj + 0x10) - *(f32 *)(obj + 0x84));
        *(f32 *)(state + 0x498) = *(f32 *)(obj + 0x28);
    }
    if (state[0x3d6] == 0) {
        if ((*(s16 *)(*(int *)(obj + 0x54) + 0x60) & 8) != 0
            && arrayIndexOf(lbl_8032855C, 10, *(s16 *)(other + 0x46)) == -1) {
        } else {
            if (*(void **)(state + 0x42c) == NULL) {
                goto clamp;
            }
            if (*(f32 *)(state + 0x3e0) <= lbl_803E5AEC) {
                goto clamp;
            }
        }
    }
    mag = PSVECMag((f32 *)(obj + 0x24));
    if (mag > lbl_803E5AEC) {
        if (!((HaloSnowBikeFlags *)(state + 0x428))->b02) {
            doRumble(lbl_803E5BC4 * mag);
        }
        *(f32 *)(state + 0x430) = *(f32 *)(state + 0x430) * lbl_803E5BBC;
        if (*(s16 *)(obj + 0x46) == 114 || *(s16 *)(obj + 0x46) == 908) {
            vol = (int)(lbl_803E5C4C * mag);
            if (vol > 80) {
                vol = 80;
            } else if (vol < 30) {
                vol = 30;
            }
            if (Sfx_IsPlayingFromObjectChannel(obj, 32) == 0) {
                Sfx_PlayFromObject(obj, 956);
                Sfx_SetObjectSfxVolume(obj, 956, vol, lbl_803E5B28);
            }
        }
    }
    if (!((HaloSnowBikeFlags *)(state + 0x428))->b02 && mag > lbl_803E5BC4) {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(mag * lbl_803E5AF8);
    }
    if (*(void **)(state + 0x42c) != NULL) {
        k = lbl_803E5C00;
        OSReport(&lbl_803DC0E4, mag);
        if (*(s16 *)(*(int *)(state + 0x42c) + 0x46) == 909
            || *(s16 *)(*(int *)(state + 0x42c) + 0x46) == 910
            || *(s16 *)(*(int *)(state + 0x42c) + 0x46) == 1236) {
            k = lbl_803E5B88;
        }
        *(f32 *)(obj + 0x24) = k * (oneOverTimeDelta * (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80)));
        *(f32 *)(obj + 0x2c) = k * (oneOverTimeDelta * (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88)));
    } else {
        k2 = lbl_803E5B88;
        *(f32 *)(obj + 0x24) = k2 * (oneOverTimeDelta * (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80)));
        *(f32 *)(obj + 0x2c) = k2 * (oneOverTimeDelta * (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88)));
    }
    Matrix_TransformPoint((f32 *)(state + 0x12c), *(f32 *)(obj + 0x24), lbl_803E5AE8, *(f32 *)(obj + 0x2c),
                          (f32 *)(state + 0x494), &dummy, (f32 *)(state + 0x49c));
clamp:
    v = *(f32 *)(state + 0x494);
    lim = *(f32 *)(state + 0x47c);
    if (v < -lim) {
        c = -lim;
    } else if (v > lim) {
        c = lim;
    } else {
        c = v;
    }
    *(f32 *)(state + 0x494) = c;
    if (*(f32 *)(state + 0x494) < lbl_803E5B8C && *(f32 *)(state + 0x494) > lbl_803E5BA4) {
        *(f32 *)(state + 0x494) = lbl_803E5AE8;
    }
    v = *(f32 *)(state + 0x498);
    lim = *(f32 *)(state + 0x480);
    if (v < -lim) {
        c = -lim;
    } else if (v > lbl_803E5AEC) {
        c = lbl_803E5AEC;
    } else {
        c = v;
    }
    *(f32 *)(state + 0x498) = c;
    if (*(f32 *)(state + 0x498) < lbl_803E5B8C && *(f32 *)(state + 0x498) > lbl_803E5BA4) {
        *(f32 *)(state + 0x498) = lbl_803E5AE8;
    }
    v = *(f32 *)(state + 0x49c);
    lim = *(f32 *)(state + 0x484);
    if (v < -lim) {
        c = -lim;
    } else if (v > lim) {
        c = lim;
    } else {
        c = v;
    }
    *(f32 *)(state + 0x49c) = c;
    if (*(f32 *)(state + 0x49c) < lbl_803E5B8C && *(f32 *)(state + 0x49c) > lbl_803E5BA4) {
        *(f32 *)(state + 0x49c) = lbl_803E5AE8;
    }
    *(f32 *)(state + 0x16c) = *(f32 *)(obj + 0xc);
    *(f32 *)(state + 0x170) = *(f32 *)(obj + 0x10);
    *(f32 *)(state + 0x174) = *(f32 *)(obj + 0x14);
    *(int *)(state + 0x42c) = 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801ed014
 * EN v1.0 Address: 0x801ED014
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801ED2CC
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed014(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar1 + 0x421) = (char)param_2;
  if (param_2 == 2) {
    GameBit_Set((int)*(short *)(iVar1 + 0x448),1);
    FUN_801ecdec(param_1,iVar1);
    if ((*(byte *)(iVar1 + 0x428) >> 5 & 1) != 0) {
      *(float *)(iVar1 + 0x4b8) = lbl_803E6828;
      *(float *)(iVar1 + 0x4c0) = lbl_803E6784;
      *(float *)(iVar1 + 0x4bc) = lbl_803E682C;
      if (*(char *)(iVar1 + 0x421) == '\x02') {
        (**(code **)(*DAT_803dd6e8 + 0x58))((int)*(float *)(iVar1 + 0x4b8),0x5cd);
        (**(code **)(*DAT_803dd6e8 + 0x68))((double)lbl_803E6830);
      }
    }
    if (*(short *)(param_1 + 0x46) == 0x72) {
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6a) = 0x14;
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6b) = 0x14;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ed104
 * EN v1.0 Address: 0x801ED104
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801ED478
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed104(int param_1)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,10);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    FUN_80017814(*(uint *)(iVar3 + 0x4c8));
    iVar3 = iVar3 + 8;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 9);
  if ((*(byte *)(iVar1 + 0x428) >> 5 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ed188
 * EN v1.0 Address: 0x801ED188
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801ED4FC
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed188(int param_1,int param_2,int param_3,int param_4,int param_5,s8 renderState)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80286838();
  iVar2 = *(int *)(iVar1 + 0xb8);
  FUN_801e9c00();
  if (renderState == -1) {
    FUN_8003b818(iVar1);
    ObjPath_GetPointWorldPosition(iVar1,0,(float *)(iVar2 + 1000),(undefined4 *)(iVar2 + 0x3ec),
                 (float *)(iVar2 + 0x3f0),0);
  }
  else {
    FUN_8003b818(iVar1);
    ObjPath_GetPointWorldPosition(iVar1,0,(float *)(iVar2 + 1000),(undefined4 *)(iVar2 + 0x3ec),
                 (float *)(iVar2 + 0x3f0),0);
  }
  FUN_80286884();
  return;
}
