#include "ghidra_import.h"
#include "main/dll/DF/rope.h"
#include "main/dll/mmsh_waterspike.h"


#define SFXwmap_name 382
#define SFXar_bblast16 390

#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006920();
extern int FUN_80006a10();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017580();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern void ModelLightStruct_free(void *light);
extern uint FUN_80017720();
extern uint FUN_80017730();
extern int randomGetRange(int min, int max);
extern undefined4 FUN_80017954();
extern undefined4 FUN_80017958();
extern int FUN_80017a54();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern void Obj_FreeObject(int obj);
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjMsg_Pop();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(f32 scale);
extern int FUN_8005b398();
extern undefined4 FUN_8005fe14();
extern void queueGlowRender(void *light);
extern int FUN_800632f4();
extern undefined4 DIMbosstonsil_render();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de810;
extern undefined4 DAT_803de814;
extern f64 DOUBLE_803e5990;
extern f64 DOUBLE_803e59f0;
extern undefined4* gExpgfxInterface;
extern undefined4* gBaddieControlInterface;
extern f32 lbl_803DC074;
extern f32 lbl_803DE818;
extern f32 lbl_803DE81C;
extern f32 lbl_803DE820;
extern f32 lbl_803DE824;
extern f32 lbl_803E4CF0;
extern f32 lbl_803E4D44;
extern f32 lbl_803E5928;
extern f32 lbl_803E5934;
extern f32 lbl_803E5938;
extern f32 lbl_803E5964;
extern f32 lbl_803E5968;
extern f32 lbl_803E596C;
extern f32 lbl_803E5970;
extern f32 lbl_803E5974;
extern f32 lbl_803E5978;
extern f32 lbl_803E5984;
extern f32 lbl_803E5988;
extern f32 lbl_803E5998;
extern f32 lbl_803E599C;
extern f32 lbl_803E59A0;
extern f32 lbl_803E59A4;
extern f32 lbl_803E59A8;
extern f32 lbl_803E59AC;
extern f32 lbl_803E59B0;
extern f32 lbl_803E59B4;
extern f32 lbl_803E59B8;
extern f32 lbl_803E59BC;
extern f32 lbl_803E59C0;
extern f32 lbl_803E59C4;
extern f32 lbl_803E59C8;
extern f32 lbl_803E59D0;
extern f32 lbl_803E59D4;
extern f32 lbl_803E59D8;
extern f32 lbl_803E59DC;
extern f32 lbl_803E59E0;
extern f32 lbl_803E59E4;
extern f32 lbl_803E59E8;
extern f32 lbl_803E59F8;
extern f32 lbl_803E59FC;
extern f32 lbl_803E5A00;
extern f32 lbl_803E5A04;
extern f32 lbl_803E5A08;
extern f32 lbl_803E5A0C;
extern f32 lbl_803E5A10;
extern f32 lbl_803E5A14;
extern f32 lbl_803E5A18;

extern u8 framesThisStep;
extern f32 timeDelta;
extern undefined4 *gPartfxInterface;
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int obj, int id);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern void doRumble(f32 v);
extern void lightFn_8001db6c(int light, int v, f32 f);
extern f32 lbl_803E4D38;
extern f32 lbl_803E4D3C;
extern f32 lbl_803E4D40;
extern f32 lbl_803E4D48;
extern f32 lbl_803E4D4C;
extern f32 lbl_803E4D50;
extern f64 lbl_803E4D58;
extern f32 lbl_803E4D60;
extern f32 lbl_803E4D64;
extern f32 lbl_803E4D68;
extern f32 lbl_803E4D6C;
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern void ObjAnim_AdvanceCurrentMove(int obj, f32 a, f32 b, int c);
extern f32 lbl_803E4CD0;
extern f32 lbl_803E4CD4;
extern f32 lbl_803E4CD8;
extern f32 lbl_803E4CDC;
extern f32 lbl_803E4CE0;
extern f32 lbl_803E4CE4;
extern f32 lbl_803E4CE8;
extern f32 lbl_803E4CEC;
extern f64 lbl_803E4CF8;
extern f32 lbl_803E4D20;
extern int Curve_AdvanceAlongPath(int a, f32 f);
extern int getAngle(f32 dx, f32 dy);
extern int Obj_GetPlayerObject(void);
extern int *gRomCurveInterface;
extern f32 lbl_803E4D10;
extern f32 lbl_803E4D14;
extern f32 lbl_803E4D18;
extern f32 lbl_803E4D1C;

/*
 * --INFO--
 *
 * Function: dimbossgut2_updateTracking
 * EN v1.0 Address: 0x801BF048
 * EN v1.0 Size: 652b
 * EN v1.1 Address: 0x801BF5FC
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossgut2_updateTracking(int obj, int state)
{
  int curve;
  int r30v;
  s16 angle;
  s16 delta;
  int q;
  f32 fv;
  int player;
  int rel;

  curve = *(int *)(state + 0x40c);
  r30v = *(int *)(state + 0x3dc);
  if ((*(u16 *)(state + 0x400) & 8) != 0) {
    if ((Curve_AdvanceAlongPath(r30v, *(f32 *)(curve + 0x10)) != 0) || (*(int *)(r30v + 0x10) != 0)) {
      if ((u8)(*((u8 (***)(int))gRomCurveInterface))[0x24](r30v) != 0) {
        *(u16 *)(state + 0x400) = *(u16 *)(state + 0x400) & ~0x8;
      }
    }
    angle = (s16)(getAngle(*(f32 *)(r30v + 0x74), *(f32 *)(r30v + 0x7c)) + 0x8000);
    delta = (s16)(angle - (u16)*(s16 *)obj);
    if (delta > 0x8000) {
      delta = (s16)(delta - 0xffff);
    }
    if (delta < -0x8000) {
      delta = (s16)(delta + 0xffff);
    }
    *(s16 *)obj = angle;
    *(f32 *)(curve + 4) = *(f32 *)(curve + 4) + (f32)(delta >> 4);
    if (*(f32 *)(curve + 0x10) < lbl_803E4D14) {
      *(f32 *)(curve + 0x10) = *(f32 *)(curve + 0x10) + lbl_803E4D18;
    }
    q = delta / 0xb6;
    if (q < 0) {
      q = -q;
    }
    fv = (f32)(s32)q * lbl_803E4CD4;
    if (lbl_803E4CF0 < fv) {
      *(f32 *)(curve + 0x10) = *(f32 *)(curve + 0x10) / fv;
      *(f32 *)(curve + 8) = *(f32 *)(curve + 8) + lbl_803E4D1C;
    }
    if (lbl_803E4CD8 < *(f32 *)(curve + 8)) {
      *(f32 *)(curve + 8) = *(f32 *)(curve + 8) / lbl_803E4D10;
    }
    *(f32 *)(obj + 0xc) = *(f32 *)(r30v + 0x68);
    *(f32 *)(obj + 0x14) = *(f32 *)(r30v + 0x70);
  }
  else {
    player = Obj_GetPlayerObject();
    rel = (int)(u16)getAngle(-(*(f32 *)(player + 0x18) - *(f32 *)(obj + 0x18)),
                             -(*(f32 *)(player + 0x20) - *(f32 *)(obj + 0x20))) -
          (int)(u16)*(s16 *)obj;
    if (rel > 0x8000) {
      rel = rel - 0xffff;
    }
    if (rel < -0x8000) {
      rel = rel + 0xffff;
    }
    *(s16 *)obj = (s16)(*(s16 *)obj + rel * (u8)framesThisStep / 3);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbossgut2_free
 * EN v1.0 Address: 0x801BF2F0
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801BF8A4
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dimbossgut2_free(int param_9)
{
  int obj = param_9;
  uint uVar1;
  int iVar2;
  void *childObj;

  iVar2 = *(int *)(obj + 0xb8);
  uVar1 = *(uint *)(*(int *)(iVar2 + 0x40c) + 0x18);
  if (uVar1 != 0) {
    ModelLightStruct_free((void *)uVar1);
  }
  ObjGroup_RemoveObject(obj,3);
  childObj = *(void **)(obj + 200);
  if (childObj != 0) {
    Obj_FreeObject((int)childObj);
    *(undefined4 *)(obj + 200) = 0;
  }
  (*(void (*)(int,int,int))(*(int *)(*gBaddieControlInterface + 0x40)))(obj,iVar2,0);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dimbossgut2_render
 * EN v1.0 Address: 0x801BF37C
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801BF930
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void dimbossgut2_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  u8 *light;

  light = *(u8 **)(param_1 + 0xb8);
  if (visible != 0) {
    ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(param_1, param_2, param_3, param_4, param_5, lbl_803E4CF0);
    light = *(u8 **)(*(int *)(light + 0x40c) + 0x18);
    if (((light != 0) && (light[0x2f8] != 0)) && (light[0x4c] != 0)) {
      queueGlowRender(light);
    }
  }
  return;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dimbossgut2_update
 * EN v1.0 Address: 0x801BF3E8
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801BF99C
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossgut2_update(int obj)
{
  int state;
  int iVar;
  uint uVar2;
  uint n;
  float *pfVar4;
  int iVar1;
  f32 fdiff;
  f32 fscale;
  u8 *p;
  uint msgA;
  uint msgB;
  uint msgC;
  struct {
    u8 pad[8];
    f32 f54;
    f32 f50;
    f32 f4c;
    f32 f48;
  } stk;

  state = *(int *)(obj + 0xb8);
  if ((*(int *)(obj + 0xf4) == 0) &&
     ((*(void **)(obj + 0x30) != NULL ||
      (iVar = objPosToMapBlockIdx(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14)),
      iVar >= 0)))) {
    msgC = 0;
    do {
      iVar = ObjMsg_Pop(obj, &msgA, &msgB, &msgC);
    } while (iVar != 0);
    pfVar4 = *(float **)(state + 0x40c);
    if ((*pfVar4 < lbl_803E4CD0) && (pfVar4[4] < lbl_803E4CD4)) {
      fdiff = pfVar4[3] - *(f32 *)(obj + 0x10);
      if (fdiff < lbl_803E4CD8) {
        fdiff = -fdiff;
      }
      if ((fdiff < lbl_803E4CDC) &&
         (stk.f4c = pfVar4[3], uVar2 = randomGetRange(0x1e, 0x3c),
         (int)(uint)*(u16 *)((int)pfVar4 + 0x16) > (int)uVar2)) {
        fscale = lbl_803E4CE0 * pfVar4[4];
        stk.f50 = *(f32 *)(obj + 0xc) -
                  fscale * fn_80293E80(lbl_803E4CE4 * (f32)*(s16 *)obj / lbl_803E4CE8);
        stk.f48 = *(f32 *)(obj + 0x14) -
                  fscale * sin(lbl_803E4CE4 * (f32)*(s16 *)obj / lbl_803E4CE8);
        stk.f54 = lbl_803E4CEC * (lbl_803E4CF0 - fdiff / lbl_803E4CDC);
        (*((int (***)(int, int, void *, int, int, int))gPartfxInterface))[2](
            obj, 0x32b, &stk, 1, -1, 0);
        *(u16 *)((int)pfVar4 + 0x16) = 0;
      }
    }
    *(u16 *)((int)pfVar4 + 0x16) = *(u16 *)((int)pfVar4 + 0x16) + (u8)framesThisStep;
    fn_801BEEA0((s16 *)obj, (u8 *)state);
    dimbossgut2_updateTracking(obj, state);
    ObjAnim_AdvanceCurrentMove(obj, lbl_803E4D20, timeDelta, 0);
    *(u8 *)(*(int *)(obj + 0x54) + 0x6e) = 9;
    *(u8 *)(*(int *)(obj + 0x54) + 0x6f) = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    iVar1 = *(int *)(state + 0x40c);
    p = *(u8 **)(iVar1 + 0x18);
    if ((p != NULL) && (p[0x2f8] != 0) && (p[0x4c] != 0)) {
      n = (p[0x2f9] + *(s8 *)(p + 0x2fa)) & 0xffff;
      if (0xc < n) {
        n = (n + randomGetRange(-12, 12)) & 0xffff;
        if (0xff < n) {
          n = 0xff;
          *(u8 *)(*(int *)(iVar1 + 0x18) + 0x2fa) = 0;
        }
      }
      *(u8 *)(*(int *)(iVar1 + 0x18) + 0x2f9) = (u8)n;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbossgut2_init
 * EN v1.0 Address: 0x801BF6B4
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x801BFC68
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int **out, int a, int b);
extern void ObjAnim_SetCurrentMove(int obj, f32 t, int a, int b);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void *objCreateLight(int obj, int n);
extern void modelLightStruct_setField50(int light, int v);
extern void modelLightStruct_setColorsA8AC(int light, int a, int b, int c, int d);
extern void lightDistAttenFn_8001dc38(int light, f32 a, f32 b);
extern void fn_8001D730(int light, int a, int b, int c, int d, int e, f32 f);
extern void fn_8001D714(int light, f32 f);
extern f32 lbl_803E4D24;
extern f32 lbl_803E4D28;
extern f32 lbl_803E4D2C;
extern f32 lbl_803E4D30;
extern f32 lbl_803E4D04;

void dimbossgut2_init(int obj, int def, int p3)
{
  int state;
  int p;
  int count;
  int i;
  int *list;
  u8 flags;
  f32 z;

  state = *(int *)(obj + 0xb8);
  flags = 0x16;
  if (p3 != 0) {
    flags |= 1;
  }
  (*(void (*)(int, int, int, int, int, int, u8, f32))(*(int *)(*gBaddieControlInterface + 0x58)))(
      obj, def, state, 0, 0, 0x102, flags, lbl_803E4CE0);
  *(int *)(obj + 0xbc) = 0;
  p = *(int *)(state + 0x40c);
  z = lbl_803E4CD8;
  *(f32 *)(p + 0x0) = z;
  *(f32 *)(p + 0x4) = z;
  *(s16 *)(p + 0x14) = randomGetRange(-0x7fff, 0x7fff);
  z = lbl_803E4CD8;
  *(f32 *)(p + 0x8) = z;
  *(s16 *)(p + 0x16) = 0;
  *(f32 *)(p + 0x10) = z;
  count = hitDetectFn_80065e50(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14), &list, 0, 0);
  *(f32 *)(p + 0xc) = lbl_803E4CD8;
  if (count != 0) {
    *(f32 *)(p + 0xc) = lbl_803E4D24;
    for (i = 0; i < count; i++) {
      f32 d = *(f32 *)list[i] - *(f32 *)(obj + 0x10);
      if (*(s8 *)(list[i] + 0x14) == 0xe) {
        if (d > *(f32 *)(p + 0xc)) {
          *(f32 *)(p + 0xc) = d;
        }
      }
    }
  }
  *(f32 *)(p + 0xc) += *(f32 *)(obj + 0x10);
  ObjAnim_SetCurrentMove(obj, (f32)(int)randomGetRange(0, 0x63) / lbl_803E4D28, 0, 0);
  ObjAnim_AdvanceCurrentMove(obj, lbl_803E4D20, timeDelta, 0);
  *(int *)(p + 0x18) = (int)objCreateLight(obj, 1);
  if (*(void **)(p + 0x18) != NULL) {
    modelLightStruct_setField50(*(int *)(p + 0x18), 2);
    modelLightStruct_setColorsA8AC(*(int *)(p + 0x18), 0, 255, 0, 0);
    lightSetFieldBC_8001db14(*(int *)(p + 0x18), 1);
    lightDistAttenFn_8001dc38(*(int *)(p + 0x18), lbl_803E4D2C, lbl_803E4CE0);
    fn_8001D730(*(int *)(p + 0x18), 0, 0, 255, 0, 127, lbl_803E4D30);
    fn_8001D714(*(int *)(p + 0x18), lbl_803E4D04);
  }
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_updateBurst
 * EN v1.0 Address: 0x801BF8D8
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801BFE8C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossspit_updateBurst(int obj)
{
  int state;
  s16 v;
  int iVar;
  int n;
  int radius;
  int i;

  state = *(int *)(obj + 0xb8);
  *(f32 *)(obj + 8) = *(f32 *)(obj + 8) + lbl_803E4D38;
  *(s16 *)(obj + 0) = *(s16 *)(obj + 0) + 0xaaa;
  *(s16 *)(obj + 4) = *(s16 *)(obj + 4) + 0x38e;
  *(s16 *)(obj + 2) = *(s16 *)(obj + 2) + 0x38e;
  if (*(s16 *)state == 1) {
    i = 0;
    do {
      (*((int (***)(int, int, int, int, int, int))gPartfxInterface))[2](obj, 0x340, 0, 1, -1, 0);
      i = i + 1;
    } while (i < 0x12);
    (*((int (***)(int, int, int, int, int, int))gPartfxInterface))[2](obj, 0x4bb, 0, 1, -1, 0);
    Sfx_PlayFromObject(obj, SFXwmap_name);
    Sfx_PlayFromObject(obj, SFXar_bblast16);
    CameraShake_SetAllMagnitudes(lbl_803E4D3C);
    doRumble(lbl_803E4D40);
    if (*(void **)(state + 4) != NULL) {
      lightFn_8001db6c(*(int *)(state + 4), 0, lbl_803E4D44);
    }
  }
  *(s16 *)state = *(s16 *)state + (u8)framesThisStep;
  v = *(s16 *)state;
  if (v > 0x200) {
    if (v > 0x22a) {
      Obj_FreeObject(obj);
    }
    return;
  }
  iVar = (int)(lbl_803E4D48 * ((f32)(s32)v * lbl_803E4D4C));
  n = 0xff - iVar;
  radius = 0x94 - (v >> 2);
  if (n >= 0) {
    ObjHits_SetHitVolumeSlot(obj, 5, 2, 0);
    ObjHitbox_SetSphereRadius(obj, (s16)((radius - 0x40) >> 1));
    *(u8 *)(obj + 0x36) = (u8)n;
  }
  else {
    if (*(void **)(state + 4) != NULL) {
      ModelLightStruct_free(*(void **)(state + 4));
      *(int *)(state + 4) = 0;
    }
    *(u8 *)(obj + 0x36) = 0;
    if ((f32)(s32)((radius - 0x40) >> 1) > lbl_803E4D50) {
      ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
      ObjHitbox_SetSphereRadius(obj, (s16)((radius - 0x40) >> 1));
    }
  }
  (*((int (***)(int, int, int, int, int, int))gPartfxInterface))[2](obj, 0x4bc, 0, 1, -1, (int)&radius);
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_free
 * EN v1.0 Address: 0x801BFB70
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801C0124
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void DIMbossspit_free(int param_1)
{
  int obj = param_1;
  uint uVar1;

  uVar1 = *(uint *)(*(int *)(obj + 0xb8) + 4);
  if (uVar1 != 0) {
    ModelLightStruct_free((void *)uVar1);
  }
  (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: DIMbossspit_render
 * EN v1.0 Address: 0x801BFBC4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801C0178
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void DIMbossspit_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  u8 *light;

  light = *(u8 **)(param_1 + 0xb8);
  if (visible != 0) {
    ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(param_1, param_2, param_3, param_4, param_5, lbl_803E4D44);
    light = *(u8 **)(light + 4);
    if (((light != 0) && (light[0x2f8] != 0)) && (light[0x4c] != 0)) {
      queueGlowRender(light);
    }
  }
  return;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: DIMbossspit_update
 * EN v1.0 Address: 0x801BFC2C
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801C01E0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossspit_update(int obj)
{
  int state;
  s16 v;
  u8 *p;
  int i;

  state = *(int *)(obj + 0xb8);
  if (*(s16 *)state == 0) {
    *(int *)(obj + 0xf4) = *(int *)(obj + 0xf4) - (u8)framesThisStep;
    if (*(int *)(obj + 0xf4) < 0) {
      Obj_FreeObject(obj);
      return;
    }
    ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
    ObjHitbox_SetSphereRadius(obj, 10);
    *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) - lbl_803E4D60 * timeDelta;
    *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) * lbl_803E4D64;
    *(s16 *)(obj + 0) = (int)(lbl_803E4D68 * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 4) = (int)(lbl_803E4D6C * timeDelta + (f32)*(s16 *)(obj + 4));
    *(s16 *)(obj + 2) = (int)(lbl_803E4D6C * timeDelta + (f32)*(s16 *)(obj + 2));
    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);
    i = 0;
    do {
      (*((int (***)(int, int, int, int, int, int))gPartfxInterface))[2](obj, 0x4ba, 0, 1, -1, 0);
      i = i + 1;
    } while (i < 3);
    if (*(s8 *)(*(int *)(obj + 0x54) + 0xad) != 0) {
      *(f32 *)(obj + 0xc) = *(f32 *)(*(int *)(obj + 0x54) + 0x3c);
      *(f32 *)(obj + 0x10) = *(f32 *)(*(int *)(obj + 0x54) + 0x40) - lbl_803E4D50;
      *(f32 *)(obj + 0x14) = *(f32 *)(*(int *)(obj + 0x54) + 0x44);
      *(s16 *)state = 1;
    }
  }
  else {
    DIMbossspit_updateBurst(obj);
  }
  p = *(u8 **)(state + 4);
  if (p != NULL && p[0x2f8] != 0 && p[0x4c] != 0) {
    v = (s16)(p[0x2f9] + *(s8 *)(p + 0x2fa));
    if (v < 0) {
      v = 0;
      p[0x2fa] = 0;
    }
    else if (v > 0xc) {
      v = (s16)(v + randomGetRange(-12, 12));
      if (v > 0xff) {
        v = 0xff;
        (*(u8 **)(state + 4))[0x2fa] = 0;
      }
    }
    (*(u8 **)(state + 4))[0x2f9] = (u8)v;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: DIMbossspit_init
 * EN v1.0 Address: 0x801BFEB4
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x801C0468
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *objCreateLight(int obj, int n);
extern void modelLightStruct_setField50(int light, int v);
extern void modelLightStruct_setColorsA8AC(int light, int a, int b, int c, int d);
extern void modelLightStruct_setColors100104(int light, int a, int b, int c, int d);
extern void lightDistAttenFn_8001dc38(int light, f32 a, f32 b);
extern void lightSetField4D(int light, int v);
extern void lightFn_8001db6c(int light, int v, f32 f);
extern void lightSetField2FB(int light, int v);
extern void fn_8001D730(int light, int a, int b, int c, int d, int e, f32 f);
extern void fn_8001D714(int light, f32 f);
extern int Obj_GetActiveModel(int obj);
extern void ObjModel_SetPostRenderCallback(int model, void *cb);
extern void fn_800284CC(void);
extern f32 lbl_803E4D70;
extern f32 lbl_803E4D74;
extern f32 lbl_803E4D78;
extern f32 lbl_803E4D7C;
extern f32 lbl_803E4D80;

void DIMbossspit_init(int obj)
{
  u8 *state = *(u8 **)(obj + 0xb8);

  *(void **)(state + 4) = objCreateLight(obj, 1);
  if (*(void **)(state + 4) != NULL) {
    modelLightStruct_setField50(*(int *)(state + 4), 2);
    modelLightStruct_setColorsA8AC(*(int *)(state + 4), 0, 255, 0, 0);
    modelLightStruct_setColors100104(*(int *)(state + 4), 0, 255, 0, 0);
    lightDistAttenFn_8001dc38(*(int *)(state + 4), lbl_803E4D70, lbl_803E4D74);
    lightSetField4D(*(int *)(state + 4), 1);
    lightFn_8001db6c(*(int *)(state + 4), 1, lbl_803E4D78);
    lightSetField2FB(*(int *)(state + 4), 1);
    fn_8001D730(*(int *)(state + 4), 0, 0, 255, 0, 127, lbl_803E4D7C);
    fn_8001D714(*(int *)(state + 4), lbl_803E4D80);
  }
  *(int *)(obj + 0xf4) = 0xb4;
  ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
  ObjHitbox_SetSphereRadius(obj, 0);
  *(s16 *)(state + 0) = 0;
  *(s16 *)(state + 2) = 0;
  ObjHits_EnableObject(obj);
  ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fn_800284CC);
}


/* Trivial 4b 0-arg blr leaves. */
void dimbossgut2_func11(void) {}
void dimbossgut2_hitDetect(void) {}
void dimbossgut2_release(void) {}
void dimbossgut2_initialise(void) {}
void DIMbossspit_hitDetect(void) {}
void DIMbossspit_release(void) {}
void DIMbossspit_initialise(void) {}
void magicmaker_free(void) {}
void magicmaker_hitDetect(void) {}
void magicmaker_init(void) {}
void magicmaker_release(void) {}
void magicmaker_initialise(void) {}
void dimbosscrackpar_hitDetect(void) {}
void dimbosscrackpar_release(void) {}
void dimbosscrackpar_initialise(void) {}

/*
 * --INFO--
 *
 * Function: magicmaker_update
 * EN v1.0 Address: 0x801C0080
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 Obj_IsLoadingLocked(void);
extern void GameBit_Set(int eventId, int value);
extern int *ObjGroup_GetObjects(int group, int *countOut);
extern char *Obj_AllocObjectSetup(int size, int typeId);
extern char *Obj_SetupObject(char *setup, int a, int b, int c, int d);
extern void hitDetectFn_80097070(char *obj, f32 f, int a, int b, int c, int d);
extern u16 lbl_80325CE8[];
extern f64 lbl_803E4D90;
extern f32 lbl_803E4D8C;
extern f32 lbl_803E4D88;

void magicmaker_update(int obj)
{
  int def;
  char *newobj;
  int n;
  int count;
  int *objs;
  int i;
  int j;
  char *setup;
  int o;

  def = *(int *)(obj + 0x4c);
  if (Obj_IsLoadingLocked() != 0) {
    if ((u32)GameBit_Get(0x26b) != 0u) {
      GameBit_Set(0x26b, 0);
      objs = ObjGroup_GetObjects(4, &count);
      n = 0;
      for (i = 0; i < count; i++) {
        o = *objs;
        for (j = 0; j < 6; j++) {
          if (*(s16 *)(o + 0x46) == lbl_80325CE8[j]) {
            n++;
          }
        }
        objs++;
      }
      if (n < 10) {
        setup = Obj_AllocObjectSetup(0x30, lbl_80325CE8[randomGetRange(0, 5)]);
        if (setup != NULL) {
          *(u8 *)(setup + 0x1a) = 0x14;
          *(s16 *)(setup + 0x2c) = -1;
          *(s16 *)(setup + 0x1c) = -1;
          *(f32 *)(setup + 0x8) = *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-0x15e, 0x15e);
          *(f32 *)(setup + 0xc) = lbl_803E4D8C + *(f32 *)(obj + 0x10);
          *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-0x15e, 0x15e);
          *(s16 *)(setup + 0x24) = -1;
          *(u8 *)(setup + 0x4) = *(u8 *)(def + 0x4);
          *(u8 *)(setup + 0x6) = *(u8 *)(def + 0x6);
          *(u8 *)(setup + 0x5) = *(u8 *)(def + 0x5);
          *(u8 *)(setup + 0x7) = *(u8 *)(def + 0x7);
          *(s16 *)(setup + 0x2e) = 3;
          newobj = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
          if (newobj != NULL) {
            i = 3;
            do {
              hitDetectFn_80097070(newobj, lbl_803E4D88, 2, 2, 0x64, 0);
              i--;
            } while (i != 0);
          }
        }
      }
    }
  }
}

extern f32 lbl_803E4D98;
extern undefined4 *gPartfxInterface;
#pragma scheduling off
#pragma peephole off
int dimbosscrackpar_SeqFn(int *obj) {
    int *side = *(int **)((char *)obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)((char *)side + 0x1e)) == 0u) {
        return 0;
    }
    (*((int (***)(int *, int, int, int, int, int))gPartfxInterface))[2](
        obj, *(s16 *)((char *)side + 0x1a) + 1222, 0, 2, -1, 0);
    (*((int (***)(int *, int, int, int, int, int))gPartfxInterface))[2](
        obj, 1224, 0, 2, -1, 0);
    return 0;
}
void dimbosscrackpar_update(int *obj) {
    int *side = *(int **)((char *)obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)((char *)side + 0x1e)) != 0u) {
        (*((int (***)(int *, int, int, int, int, int))gPartfxInterface))[2](
            obj, *(s16 *)((char *)side + 0x1a) + 1222, 0, 2, -1, 0);
        (*((int (***)(int *, int, int, int, int, int))gPartfxInterface))[2](
            obj, 1224, 0, 2, -1, 0);
    }
}
void dimbosscrackpar_free(int *obj) {
    (*(void (*)(int *))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
void dimbosscrackpar_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
void dimbosscrackpar_init(s16 *obj, s8 *def) {
    obj[0] = 0;
    *(f32 *)((char *)obj + 8) = lbl_803E4D98;
    *(int *)((char *)obj + 0xbc) = (int)&dimbosscrackpar_SeqFn;
    obj[0] = (s16)((s32)def[0x24] << 8);
    obj[1] = (s16)((s32)def[0x23] << 8);
    obj[2] = (s16)((s32)def[0x22] << 8);
}
#pragma peephole reset
#pragma scheduling reset
void dimbossfire_hitDetect(void) {}

/*
 * --INFO--
 *
 * Function: dimbossfire_free
 * EN v1.0 Address: 0x801C04C8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dimbossfire_free(int obj)
{
  int o = obj;
  int state;
  void *light;

  state = *(int *)(o + 0xb8);
  light = *(void **)(state + 0x10);
  if (light != 0) {
    ModelLightStruct_free(light);
    *(undefined4 *)(state + 0x10) = 0;
  }
  (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(o);
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void dimbossfire_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset

/* 8b "li r3, N; blr" returners. */
int dimbossgut2_setScale(void) { return 0x0; }
int dimbossgut2_getExtraSize(void) { return 0x42c; }
int dimbossgut2_getObjectTypeId(void) { return 0x49; }
int DIMbossspit_getExtraSize(void) { return 0x8; }
int DIMbossspit_getObjectTypeId(void) { return 0x0; }
int magicmaker_getExtraSize(void) { return 0x0; }
int magicmaker_getObjectTypeId(void) { return 0x0; }
int dimbosscrackpar_getExtraSize(void) { return 0x0; }
int dimbosscrackpar_getObjectTypeId(void) { return 0x0; }
int dimbossfire_getExtraSize(void) { return 0x14; }
int dimbossfire_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4D88;
#pragma peephole off
void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4D88); }
#pragma peephole reset
