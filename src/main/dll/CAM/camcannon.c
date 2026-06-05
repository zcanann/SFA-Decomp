#include "ghidra_import.h"
#include "main/dll/CAM/camcannon.h"


#pragma peephole off
#pragma scheduling off
extern f32 Curve_EvalLinear(f32 param_1, float *param_2, float *param_3);
extern f32 Curve_EvalHermite(f32 param_1, float *param_2, float *param_3);
extern undefined4 FUN_80017814();
extern f32 sqrtf(f32 x);

extern int *gCameraInterface;
extern undefined4 lbl_803DD560;
extern f64 lbl_803E18A0;
extern f32 timeDelta;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 lbl_803E1890;
extern f32 lbl_803E1894;
extern f32 lbl_803E1898;
extern f32 lbl_803E18AC;
extern f32 lbl_803E18B0;
extern f32 lbl_803E18B4;
extern f32 lbl_803E18B8;

/*
 * --INFO--
 *
 * Function: fn_8010AEA8
 * EN v1.0 Address: 0x8010AEA8
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x8010B144
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint fn_8010AEA8(s16 *st, uint flagsIn)
{
  u8 flags;
  f32 d;
  f32 t;
  f32 q;

  *(f32 *)(lbl_803DD560 + 0x14) = *(f32 *)(st + 6);
  *(f32 *)(lbl_803DD560 + 0x1c) = *(f32 *)(st + 8);
  *(f32 *)(lbl_803DD560 + 0x24) = *(f32 *)(st + 10);
  *(f32 *)(lbl_803DD560 + 0x2c) = (f32)st[0];
  *(f32 *)(lbl_803DD560 + 0x34) = (f32)st[1];
  *(f32 *)(lbl_803DD560 + 0x3c) = (f32)st[2];
  *(f32 *)(lbl_803DD560 + 0x44) = *(f32 *)(st + 0x5a);

  if (lbl_803E1888 != *(f32 *)(lbl_803DD560 + 0x60)) {
    t = *(f32 *)(lbl_803DD560 + 0x5c) / *(f32 *)(lbl_803DD560 + 0x60);
  } else {
    t = lbl_803E1888;
  }
  if (t > lbl_803E188C) {
    t = lbl_803E188C;
  }
  t = Curve_EvalHermite(t, (f32 *)(lbl_803DD560 + 0x48), (f32 *)0x0);
  if (t < lbl_803E18AC) {
    t = lbl_803E18AC;
  }
  *(f32 *)(lbl_803DD560 + 0x5c) = t * timeDelta + *(f32 *)(lbl_803DD560 + 0x5c);

  q = lbl_803E1888;
  if (q != *(f32 *)(lbl_803DD560 + 0x60)) {
    q = *(f32 *)(lbl_803DD560 + 0x5c) / *(f32 *)(lbl_803DD560 + 0x60);
  }
  if (q > lbl_803E188C) {
    q = lbl_803E188C;
  }
  *(f32 *)(st + 6) = Curve_EvalLinear(q, (f32 *)(lbl_803DD560 + 0x10), (f32 *)0x0);
  *(f32 *)(st + 8) = Curve_EvalLinear(q, (f32 *)(lbl_803DD560 + 0x18), (f32 *)0x0);
  *(f32 *)(st + 10) = Curve_EvalLinear(q, (f32 *)(lbl_803DD560 + 0x20), (f32 *)0x0);
  *(f32 *)(st + 0x5a) = Curve_EvalLinear(q, (f32 *)(lbl_803DD560 + 0x40), (f32 *)0x0);

  d = *(f32 *)(lbl_803DD560 + 0x28) - *(f32 *)(lbl_803DD560 + 0x2c);
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (*(f32 *)(lbl_803DD560 + 0x28) < lbl_803E1888) {
      *(f32 *)(lbl_803DD560 + 0x28) = *(f32 *)(lbl_803DD560 + 0x28) + lbl_803E1898;
    }
    else if (*(f32 *)(lbl_803DD560 + 0x2c) < lbl_803E1888) {
      *(f32 *)(lbl_803DD560 + 0x2c) = *(f32 *)(lbl_803DD560 + 0x2c) + lbl_803E1898;
    }
  }
  d = *(f32 *)(lbl_803DD560 + 0x30) - *(f32 *)(lbl_803DD560 + 0x34);
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (*(f32 *)(lbl_803DD560 + 0x30) < lbl_803E1888) {
      *(f32 *)(lbl_803DD560 + 0x30) = *(f32 *)(lbl_803DD560 + 0x30) + lbl_803E1898;
    }
    else if (*(f32 *)(lbl_803DD560 + 0x34) < lbl_803E1888) {
      *(f32 *)(lbl_803DD560 + 0x34) = *(f32 *)(lbl_803DD560 + 0x34) + lbl_803E1898;
    }
  }
  d = *(f32 *)(lbl_803DD560 + 0x38) - *(f32 *)(lbl_803DD560 + 0x3c);
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (*(f32 *)(lbl_803DD560 + 0x38) < lbl_803E1888) {
      *(f32 *)(lbl_803DD560 + 0x38) = *(f32 *)(lbl_803DD560 + 0x38) + lbl_803E1898;
    }
    else if (*(f32 *)(lbl_803DD560 + 0x3c) < lbl_803E1888) {
      *(f32 *)(lbl_803DD560 + 0x3c) = *(f32 *)(lbl_803DD560 + 0x3c) + lbl_803E1898;
    }
  }

  flags = flagsIn;
  if ((flags & 1) == 0) {
    st[0] = (s16)(int)Curve_EvalLinear(q, (f32 *)(lbl_803DD560 + 0x28), (f32 *)0x0);
  }
  if ((flags & 2) == 0) {
    st[1] = (s16)(int)Curve_EvalLinear(q, (f32 *)(lbl_803DD560 + 0x30), (f32 *)0x0);
  }
  if ((flags & 4) == 0) {
    st[2] = (s16)(int)Curve_EvalLinear(q, (f32 *)(lbl_803DD560 + 0x38), (f32 *)0x0);
  }
  return q >= lbl_803E188C;
}

/*
 * --INFO--
 *
 * Function: cameraModeTestStrengthFn_8010b238
 * EN v1.0 Address: 0x8010B218
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x8010B4D4
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cameraModeTestStrengthFn_8010b238(f32 param_1, s16 *param_2, f32 *param_3, s32 param_4, s32 param_5,
                 s32 param_6)
{
  f32 fVar1;
  f32 fVar2;
  f32 fVar3;
  int camState;

  *(u8 *)(lbl_803DD560 + 100) = 0;
  *(f32 *)(lbl_803DD560 + 0x10) = *(f32 *)((int)param_2 + 12);
  *(f32 *)(lbl_803DD560 + 0x18) = *(f32 *)((int)param_2 + 16);
  *(f32 *)(lbl_803DD560 + 0x20) = *(f32 *)((int)param_2 + 20);
  *(f32 *)(lbl_803DD560 + 0x28) = (f32)(s32)param_2[0];
  *(f32 *)(lbl_803DD560 + 0x30) = (f32)(s32)param_2[1];
  *(f32 *)(lbl_803DD560 + 0x38) = (f32)(s32)param_2[2];
  *(f32 *)(lbl_803DD560 + 0x40) = *(f32 *)((int)param_2 + 0xb4);
  *(f32 *)(lbl_803DD560 + 0x14) = param_3[0];
  *(f32 *)(lbl_803DD560 + 0x1c) = param_3[1];
  *(f32 *)(lbl_803DD560 + 0x24) = param_3[2];
  *(f32 *)(lbl_803DD560 + 0x2c) = (f32)param_4;
  *(f32 *)(lbl_803DD560 + 0x34) = (f32)param_5;
  *(f32 *)(lbl_803DD560 + 0x3c) = (f32)param_6;
  *(f32 *)(lbl_803DD560 + 0x44) = param_1;
  *(f32 *)(lbl_803DD560 + 0x5c) = lbl_803E1888;
  fVar1 = *(f32 *)(lbl_803DD560 + 0x14) - *(f32 *)(lbl_803DD560 + 0x10);
  fVar2 = *(f32 *)(lbl_803DD560 + 0x1c) - *(f32 *)(lbl_803DD560 + 0x18);
  fVar3 = *(f32 *)(lbl_803DD560 + 0x24) - *(f32 *)(lbl_803DD560 + 0x20);
  *(f32 *)(lbl_803DD560 + 0x60) = sqrtf(fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3);
  camState = lbl_803DD560;
  (**(void (**)(int, f64, f64, f64, f64, f64))(*gCameraInterface + 0x34))
            (camState + 0x48, (f64)*(f32 *)(camState + 0x60), (f64)lbl_803E18B0,
             (f64)lbl_803E18B4, (f64)lbl_803E18B4, (f64)lbl_803E18B8);
}

/*
 * --INFO--
 *
 * Function: FUN_8010b428
 * EN v1.0 Address: 0x8010B428
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010B694
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010b428(void)
{
  FUN_80017814(lbl_803DD560);
  lbl_803DD560 = 0;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeTestStrength_copyToCurrent_nop(void) {}

/* fn_X(lbl); lbl = 0; */
extern u32 lbl_803DD560;
extern void mm_free(u32);
#pragma scheduling off
#pragma peephole off
void CameraModeTestStrength_free(void) { mm_free(lbl_803DD560); lbl_803DD560 = 0; }
#pragma peephole reset
#pragma scheduling reset
