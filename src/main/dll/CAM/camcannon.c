#include "main/dll/CAM/camcannon.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camcannon_state.h"


#pragma peephole off
#pragma scheduling off
extern f32 Curve_EvalLinear(f32 param_1, float *param_2, float *param_3);
extern f32 Curve_EvalHermite(f32 param_1, float *param_2, float *param_3);
extern undefined4 FUN_80017814();
extern f32 sqrtf(f32 x);

extern CamCannonState *lbl_803DD560;
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
  CamCannonState *state;
  u8 flags;
  f32 d;
  f32 t;
  f32 q;

  state = lbl_803DD560;
  state->posXEnd = *(f32 *)(st + 6);
  state->posYEnd = *(f32 *)(st + 8);
  state->posZEnd = *(f32 *)(st + 10);
  state->rotXEnd = (f32)st[0];
  state->rotYEnd = (f32)st[1];
  state->rotZEnd = (f32)st[2];
  state->fovEnd = *(f32 *)(st + 0x5a);

  if (lbl_803E1888 != state->duration) {
    t = state->elapsed / state->duration;
  } else {
    t = lbl_803E1888;
  }
  if (t > lbl_803E188C) {
    t = lbl_803E188C;
  }
  t = Curve_EvalHermite(t, state->speedCurve, (f32 *)0x0);
  if (t < lbl_803E18AC) {
    t = lbl_803E18AC;
  }
  state->elapsed = t * timeDelta + state->elapsed;

  q = lbl_803E1888;
  if (q != state->duration) {
    q = state->elapsed / state->duration;
  }
  if (q > lbl_803E188C) {
    q = lbl_803E188C;
  }
  *(f32 *)(st + 6) = Curve_EvalLinear(q, &state->posXStart, (f32 *)0x0);
  *(f32 *)(st + 8) = Curve_EvalLinear(q, &state->posYStart, (f32 *)0x0);
  *(f32 *)(st + 10) = Curve_EvalLinear(q, &state->posZStart, (f32 *)0x0);
  *(f32 *)(st + 0x5a) = Curve_EvalLinear(q, &state->fovStart, (f32 *)0x0);

  d = state->rotXStart - state->rotXEnd;
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (state->rotXStart < lbl_803E1888) {
      state->rotXStart = state->rotXStart + lbl_803E1898;
    }
    else if (state->rotXEnd < lbl_803E1888) {
      state->rotXEnd = state->rotXEnd + lbl_803E1898;
    }
  }
  d = state->rotYStart - state->rotYEnd;
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (state->rotYStart < lbl_803E1888) {
      state->rotYStart = state->rotYStart + lbl_803E1898;
    }
    else if (state->rotYEnd < lbl_803E1888) {
      state->rotYEnd = state->rotYEnd + lbl_803E1898;
    }
  }
  d = state->rotZStart - state->rotZEnd;
  if ((d > lbl_803E1890) || (d < lbl_803E1894)) {
    if (state->rotZStart < lbl_803E1888) {
      state->rotZStart = state->rotZStart + lbl_803E1898;
    }
    else if (state->rotZEnd < lbl_803E1888) {
      state->rotZEnd = state->rotZEnd + lbl_803E1898;
    }
  }

  flags = flagsIn;
  if ((flags & 1) == 0) {
    st[0] = (s16)(int)Curve_EvalLinear(q, &state->rotXStart, (f32 *)0x0);
  }
  if ((flags & 2) == 0) {
    st[1] = (s16)(int)Curve_EvalLinear(q, &state->rotYStart, (f32 *)0x0);
  }
  if ((flags & 4) == 0) {
    st[2] = (s16)(int)Curve_EvalLinear(q, &state->rotZStart, (f32 *)0x0);
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
  CamCannonState *state;
  f32 fVar1;
  f32 fVar2;
  f32 fVar3;

  state = lbl_803DD560;
  state->transitionComplete = 0;
  state->posXStart = *(f32 *)((int)param_2 + 12);
  state->posYStart = *(f32 *)((int)param_2 + 16);
  state->posZStart = *(f32 *)((int)param_2 + 20);
  state->rotXStart = (f32)(s32)param_2[0];
  state->rotYStart = (f32)(s32)param_2[1];
  state->rotZStart = (f32)(s32)param_2[2];
  state->fovStart = *(f32 *)((int)param_2 + 0xb4);
  state->posXEnd = param_3[0];
  state->posYEnd = param_3[1];
  state->posZEnd = param_3[2];
  state->rotXEnd = (f32)param_4;
  state->rotYEnd = (f32)param_5;
  state->rotZEnd = (f32)param_6;
  state->fovEnd = param_1;
  state->elapsed = lbl_803E1888;
  fVar1 = state->posXEnd - state->posXStart;
  fVar2 = state->posYEnd - state->posYStart;
  fVar3 = state->posZEnd - state->posZStart;
  state->duration = sqrtf(fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3);
  (*gCameraInterface)->initialise(state->speedCurve, (f64)state->duration,
                                  (f64)lbl_803E18B0, (f64)lbl_803E18B4,
                                  (f64)lbl_803E18B4, (f64)lbl_803E18B8);
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
extern void mm_free(u32);
void CameraModeTestStrength_free(void) { mm_free((u32)lbl_803DD560); lbl_803DD560 = 0; }
