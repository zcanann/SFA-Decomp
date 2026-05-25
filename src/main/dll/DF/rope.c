#include "ghidra_import.h"
#include "main/dll/DF/rope.h"
#include "main/dll/dll_18E.h"


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
void dimbossgut2_updateTracking(ushort *param_1,int param_2)
{
  float fVar1;
  ushort uVar3;
  short sVar4;
  uint uVar2;
  int iVar5;
  char cVar6;
  float *pfVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_2 + 0x40c);
  pfVar7 = *(float **)(param_2 + 0x3dc);
  if ((*(ushort *)(param_2 + 0x400) & 8) == 0) {
    FUN_80017a98();
    uVar2 = FUN_80017730();
    iVar8 = (uVar2 & 0xffff) - (uint)*param_1;
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    iVar8 = iVar8 * (uint)DAT_803dc070;
    *param_1 = *param_1 +
               ((short)((ulonglong)((longlong)iVar8 * 0x55555556) >> 0x20) -
               ((short)((short)(iVar8 / 0x30000) + (short)(iVar8 >> 0x1f)) >> 0xf));
  }
  else {
    iVar5 = FUN_80006a10((double)*(float *)(iVar8 + 0x10),pfVar7);
    if (((iVar5 != 0) || (pfVar7[4] != 0.0)) &&
       (cVar6 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar7), cVar6 != '\0')) {
      *(ushort *)(param_2 + 0x400) = *(ushort *)(param_2 + 0x400) & ~0x8;
    }
    iVar5 = FUN_80017730();
    uVar3 = (short)iVar5 + 0x8000;
    sVar4 = uVar3 - *param_1;
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    *param_1 = uVar3;
    iVar5 = (int)sVar4;
    *(f32 *)(iVar8 + 4) =
         *(f32 *)(iVar8 + 4) + (f32)(s32)(iVar5 >> 4);
    if (*(f32 *)(iVar8 + 0x10) < lbl_803E59AC) {
      *(f32 *)(iVar8 + 0x10) = *(f32 *)(iVar8 + 0x10) + lbl_803E59B0;
    }
    iVar5 = iVar5 / 0xb6 + (iVar5 >> 0x1f);
    uVar2 = iVar5 - (iVar5 >> 0x1f);
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    fVar1 = (f32)(s32)uVar2 * lbl_803E596C;
    if (lbl_803E5988 < fVar1) {
      *(float *)(iVar8 + 0x10) = *(float *)(iVar8 + 0x10) / fVar1;
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) + lbl_803E59B4;
    }
    if (lbl_803E5970 < *(float *)(iVar8 + 8)) {
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) / lbl_803E59A8;
    }
    *(float *)(param_1 + 6) = pfVar7[0x1a];
    *(float *)(param_1 + 10) = pfVar7[0x1c];
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
  u8 auStack_5c[8];
  f32 local_54;
  f32 local_50;
  f32 local_4c;
  f32 local_48;

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
         (local_4c = pfVar4[3], uVar2 = randomGetRange(0x1e, 0x3c),
         (int)uVar2 < (int)(uint)*(u16 *)((int)pfVar4 + 0x16))) {
        fscale = lbl_803E4CE0 * pfVar4[4];
        local_50 = *(f32 *)(obj + 0xc) -
                   fscale * fn_80293E80(lbl_803E4CE4 * (f32)*(s16 *)obj / lbl_803E4CE8);
        local_48 = *(f32 *)(obj + 0x14) -
                   fscale * sin(lbl_803E4CE4 * (f32)*(s16 *)obj / lbl_803E4CE8);
        local_54 = lbl_803E4CEC * (lbl_803E4CF0 - fdiff / lbl_803E4CDC);
        (*((int (***)(int, int, void *, int, int, int))gPartfxInterface))[2](
            obj, 0x32b, auStack_5c, 1, -1, 0);
        *(u16 *)((int)pfVar4 + 0x16) = 0;
      }
    }
    *(u16 *)((int)pfVar4 + 0x16) = *(u16 *)((int)pfVar4 + 0x16) + (u8)framesThisStep;
    fn_801BEEA0((s16 *)obj, (u8 *)state);
    dimbossgut2_updateTracking((ushort *)obj, state);
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
    Sfx_PlayFromObject(obj, 0x17e);
    Sfx_PlayFromObject(obj, 0x186);
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
extern int objCreateLight(int obj, int n);
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

  *(int *)(state + 4) = objCreateLight(obj, 1);
  if (*(int *)(state + 4) != 0) {
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

extern f32 lbl_803E4D98;
extern undefined4 *gPartfxInterface;
#pragma scheduling off
#pragma peephole off
int fn_801C02B8(int *obj) {
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
void dimbosscrackpar_free(int *obj) {
    (*(void (*)(int *))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
void dimbosscrackpar_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
void dimbosscrackpar_init(s16 *obj, s8 *def) {
    obj[0] = 0;
    *(f32 *)((char *)obj + 8) = lbl_803E4D98;
    *(int *)((char *)obj + 0xbc) = (int)&fn_801C02B8;
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
