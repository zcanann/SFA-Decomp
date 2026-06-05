#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/campfire.h"
#include "main/objanim.h"

#define SFXfox_runbreath3 0x255
#define SFXkr_pullup1 0x270
#define SFXkr_pullup2 0x271
#define SFXkr_climb1 0x273
#define SFXkr_land1 0x275
#define SFXkr_land2 0x276

extern undefined4 FUN_80006824();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 Resource_Acquire();
extern u32 randomGetRange(int min, int max);
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject();
extern undefined4 Obj_SetModelColorFadeRecursive();
extern undefined4 ObjHitbox_SetSphereRadius();
extern u8 Obj_IsLoadingLocked();
extern undefined4 Obj_GetPlayerObject();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern void ObjGroup_RemoveObject(int obj,int group);
extern undefined4 ObjPath_GetPointWorldPosition();
extern int objFindTexture();
extern undefined4 FUN_80039520();
extern undefined4 fn_8003B5E0();
extern undefined4 objRenderFn_8003b8f4();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 objParticleFn_80099d84();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 objLightFn_8009a1dc();
extern undefined4 FUN_801695e8();
extern int FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern f32 sqrtf(f32);
extern double FUN_80293900();
extern f32 fn_80293E80(f32 x);
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294c68();
extern undefined4 fn_802961FC();

extern undefined4 DAT_802c2990;
extern undefined4 DAT_802c2994;
extern undefined4 DAT_802c2998;
extern undefined4 DAT_802c299c;
extern undefined4 lbl_802C2210[];
extern undefined4 DAT_803ad2c8;
extern undefined4 DAT_803ad2ca;
extern undefined4 DAT_803ad2cc;
extern undefined4 DAT_803ad2d0;
extern undefined4 DAT_803ad2e0;
extern undefined4 DAT_803ad2f8;
extern f32 lbl_803DDA94;
extern f32 lbl_803DDA98;
extern void* lbl_803AC680[];
extern void* lbl_803AC698[];
extern undefined4* gPartfxInterface;
extern undefined4* gPlayerInterface;
extern undefined4* gMapEventInterface;
extern undefined4* gBaddieControlInterface;
extern undefined4* lbl_803DDA90;
extern f64 DOUBLE_803e3d00;
extern f64 DOUBLE_803e3d08;
extern f32 lbl_803DC074;
extern f32 timeDelta;
extern f32 lbl_803DE714;
extern f32 lbl_803DE718;
extern f32 lbl_803E3CF8;
extern f32 lbl_803E3D10;
extern f32 lbl_803E3D14;
extern f32 lbl_803E3D24;
extern f32 lbl_803E3D2C;
extern f32 lbl_803E3D30;
extern f32 lbl_803E3D34;
extern f32 lbl_803E3D38;
extern f32 lbl_803E3D3C;
extern f32 lbl_803E3D40;
extern f32 lbl_803E3D44;
extern f32 lbl_803E3D48;
extern f32 lbl_803E3D4C;
extern f32 lbl_803E3D58;
extern f32 lbl_803E3D5C;
extern f32 lbl_803E3D60;
extern f32 lbl_803E3060;
extern f64 lbl_803E3068;
extern f64 DOUBLE_803E3070;
extern f32 lbl_803E307C;
extern f32 lbl_803E3078;
extern f32 lbl_803E308C;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30A8;
extern f32 lbl_803E30AC;
extern f32 lbl_803E30B0;
extern f32 lbl_803E30B4;
extern f32 lbl_803E30B8;
extern f32 lbl_803E30BC;
extern f32 lbl_803E30C0;
extern f32 lbl_803E30C4;
extern f32 lbl_803E30C8;
extern f32 lbl_803E30CC;

#pragma peephole off
#pragma scheduling off

extern void fn_80167764(void);
extern void fn_801678E4(void);
extern void fn_8016792C(void);
extern void fn_80167988(void);
extern void fn_80167A60(void);
extern void fn_80167AE4(void);
extern void fn_80167B60(void);
extern void fn_80167D10(void);
extern void fn_80167DA4(void);
extern void fn_80167E3C(void);
extern void fn_80167EC4(void);
extern void fn_80167F58(void);
extern void fn_80168018(void);
extern void fn_80168118(void);

/*
 * --INFO--
 *
 * Function: kaldaChomFn_8016821c
 * EN v1.0 Address: 0x80168818
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x801686C8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void kaldaChomFn_8016821c(int param_1,int *param_2)
{
  char cVar1;
  int iVar2;
  int iVar3;

  iVar3 = *(int *)(param_1 + 0x4c);
  lbl_803DDA94 =
       lbl_803E30A0 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
              DOUBLE_803E3070) / lbl_803E30A4;
  param_2[0x10] = (int)lbl_803E308C;
  Sfx_PlayFromObject(param_1,SFXkr_land2);
  iVar2 = 0x28;
  do {
    (**(code **)(*gPartfxInterface + 8))(param_1,0x717,0,4,0xffffffff,&lbl_803DDA94);
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  if ((*param_2 == 0) && (cVar1 = Obj_IsLoadingLocked(), cVar1 != '\0')) {
    iVar2 = Obj_AllocObjectSetup(0x24,0x55e);
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(float *)(iVar2 + 0xc) = lbl_803E30A8 + *(float *)(param_1 + 0x10);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)(iVar2 + 4) = *(undefined *)(iVar3 + 4);
    *(undefined *)(iVar2 + 5) = *(undefined *)(iVar3 + 5);
    *(undefined *)(iVar2 + 6) = *(undefined *)(iVar3 + 6);
    *(undefined *)(iVar2 + 7) = *(undefined *)(iVar3 + 7);
    iVar2 = Obj_SetupObject(iVar2,5,0xffffffff,0xffffffff,0);
    *param_2 = iVar2;
    *(float *)(*param_2 + 8) = lbl_803DDA94;
  }
  return;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: kaldaChomFn_80168374
 * EN v1.0 Address: 0x80168A0C
 * EN v1.0 Size: 640b
 * EN v1.1 Address: 0x80168820
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void kaldaChomFn_80168374(int param_1, int param_2, u8 param_3)
{
  int iVar4;
  int iVar3;
  u8 *setup;
  f32 h;
  f32 spd;
  f32 r;

  iVar4 = *(int *)(param_2 + 0x40c);
  iVar3 = *(int *)(param_1 + 0x4c);
  if (Obj_IsLoadingLocked() != 0) {
    h = lbl_803E30A0 + (f32)(s32)*(s8 *)(iVar3 + 0x28) / lbl_803E30A4;
    iVar3 = Obj_AllocObjectSetup(0x24, 0x51b);
    if (param_3 != 0) {
      *(f32 *)(iVar3 + 8) = *(f32 *)(iVar4 + 0x10);
      *(f32 *)(iVar3 + 0xc) = *(f32 *)(iVar4 + 0x14);
      *(f32 *)(iVar3 + 0x10) = *(f32 *)(iVar4 + 0x18);
    }
    else {
      *(f32 *)(iVar3 + 8) = *(f32 *)(iVar4 + 0x28);
      *(f32 *)(iVar3 + 0xc) = *(f32 *)(iVar4 + 0x2c);
      *(f32 *)(iVar3 + 0x10) = *(f32 *)(iVar4 + 0x30);
    }
    *(u8 *)(iVar3 + 4) = 1;
    *(u8 *)(iVar3 + 5) = 4;
    *(u8 *)(iVar3 + 6) = 0xff;
    *(u8 *)(iVar3 + 7) = 0xff;
    setup = (u8 *)Obj_SetupObject(iVar3, 5, 0xffffffff, 0xffffffff, 0);
    if (setup != NULL) {
      spd = lbl_803E30AC * (*(f32 *)(param_2 + 0x2c0) / (f32)(u32)*(u16 *)(param_2 + 0x3fe));
      *(f32 *)(setup + 0x24) =
          (*(f32 *)(*(int *)(param_2 + 0x2d0) + 0xc) - *(f32 *)(iVar3 + 8)) / spd;
      r = (f32)(s32)randomGetRange(-0xa, 0xa);
      *(f32 *)(setup + 0x28) =
          (lbl_803E30A8 * h + *(f32 *)(*(int *)(param_2 + 0x2d0) + 0x10) + r - *(f32 *)(iVar3 + 0xc)) / spd;
      *(f32 *)(setup + 0x2c) =
          (*(f32 *)(*(int *)(param_2 + 0x2d0) + 0x14) - *(f32 *)(iVar3 + 0x10)) / spd;
    }
  }
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: kaldachom_handleAnimEvents
 * EN v1.0 Address: 0x80168C8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80168A08
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void kaldachom_handleAnimEvents(int obj, int p2, int p3)
{
  int sub_40c = *(int *)(p2 + 0x40c);

  lbl_803DDA98 = lbl_803E30A0 + (f32)(s32)(s8)*(u8 *)(*(int *)(obj + 0x4c) + 0x28) / lbl_803E30A4;

  if ((*(int *)(p3 + 0x314) &0x1) != 0) {
    *(u32 *)(p3 + 0x314) = *(u32 *)(p3 + 0x314) & ~0x1;
    Sfx_PlayFromObject(obj, SFXkr_climb1);
  }
  if ((*(int *)(p3 + 0x314) &0x80) != 0) {
    int n;
    *(u8 *)(sub_40c + 0x4a) = (u8)randomGetRange(0, 2);
    *(u32 *)(p3 + 0x314) = *(u32 *)(p3 + 0x314) & ~0x80;
    Sfx_PlayFromObject(obj, SFXkr_climb2);
    for (n = (2 - (s32)*(u8 *)(sub_40c + 0x4a)) * 10; n != 0; n--) {
      (**(void (**)(int, int, int, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
          obj, 1809, 0, 4, -1, (int)&lbl_803DDA98);
    }
  }
  if ((*(int *)(p3 + 0x314) &0x40) != 0) {
    *(u32 *)(p3 + 0x314) = *(u32 *)(p3 + 0x314) & ~0x40;
    kaldaChomFn_80168374(obj, p2, 0);
  }
  if ((*(int *)(p3 + 0x314) &0x20) != 0) {
    *(u32 *)(p3 + 0x314) = *(u32 *)(p3 + 0x314) & ~0x20;
    kaldaChomFn_80168374(obj, p2, 1);
  }
  if ((*(int *)(p3 + 0x314) &0x200) != 0) {
    *(u32 *)(p3 + 0x314) = *(u32 *)(p3 + 0x314) & ~0x200;
    Sfx_PlayFromObject(obj, SFXkr_land1);
  }
  if ((*(int *)(p3 + 0x314) &0x400) != 0) {
    int n;
    *(u8 *)(sub_40c + 0x4a) = 3;
    n = 10;
    do {
      (**(void (**)(int, int, int, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
          obj, 1808, 0, 4, -1, (int)&lbl_803DDA98);
      n--;
    } while (n != 0);
    *(u32 *)(p3 + 0x314) = *(u32 *)(p3 + 0x314) & ~0x400;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: kaldachom_updateCombat
 * EN v1.0 Address: 0x80168C90
 * EN v1.0 Size: 1624b
 * EN v1.1 Address: 0x80168BF8
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct KaldaCombatParams {
    u32 a;
    u32 b;
    u32 c;
    u32 d;
} KaldaCombatParams;

typedef struct KaldaCombatStack {
    f32 dx;
    f32 dy;
    f32 dz;
    KaldaCombatParams p;
} KaldaCombatStack;

extern u8 lbl_803AC668[0x18];

#pragma push
#pragma scheduling off
#pragma peephole off
void kaldachom_updateCombat(int obj, int stateWithBaddieData, int state)
{
  int *piVar8;
  int playerObj;
  int result;
  u8 rnd;
  KaldaCombatStack st;
  u16 hitType;
  u16 hitAux1;
  u16 hitAux2;

  piVar8 = *(int **)(stateWithBaddieData + 0x40c);
  st.p = *(KaldaCombatParams *)lbl_802C2210;
  playerObj = Obj_GetPlayerObject();
  if (*(void **)(state + 0x2d0) != NULL) {
    int target = *(int *)(state + 0x2d0);
    st.dx = *(f32 *)(target + 0x18) - *(f32 *)(obj + 0x18);
    st.dy = *(f32 *)(target + 0x1c) - *(f32 *)(obj + 0x1c);
    st.dz = *(f32 *)(target + 0x20) - *(f32 *)(obj + 0x20);
    *(f32 *)(state + 0x2c0) = sqrtf(st.dz * st.dz + (st.dx * st.dx + st.dy * st.dy));
  }
  (*(void (**)(int, int, int, int, int, int, int, int))(*(int *)gBaddieControlInterface + 0x54))(
      obj, state, stateWithBaddieData + 0x35c, *(s16 *)(stateWithBaddieData + 0x3f4), 0, 0, 0, 4);
  (*(void (**)(int, int, int, u16 *, u16 *, u16 *))(*(int *)gBaddieControlInterface + 0x14))(
      obj, playerObj, 4, &hitType, &hitAux1, &hitAux2);
  if ((hitType == 1) || (hitType == 2)) {
    result = (*(int (**)(int, int, int, int, int, int, int, void *))(*(int *)gBaddieControlInterface + 0x50))(
        obj, state, stateWithBaddieData + 0x35c, *(s16 *)(stateWithBaddieData + 0x3f4), 0, 0, 1,
        lbl_803AC668);
    if (result != 0) {
      if ((result != 0x10) && (result != 0x11)) {
        objLightFn_8009a1dc(lbl_803E30BC, obj, lbl_803AC668, 3, 0);
        (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, state, 4);
        *(u8 *)(state + 0x354) -= 1;
        Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, SFXen_blkscrp6);
      }
      if (*(s8 *)(state + 0x354) < 1) {
        *(s16 *)(state + 0x270) = 2;
      }
    }
  }
  else {
    result = (*(int (**)(int, int, int, int, int, int, int, void *))(*(int *)gBaddieControlInterface + 0x50))(
        obj, state, stateWithBaddieData + 0x35c, *(s16 *)(stateWithBaddieData + 0x3f4), 0, 0, 1,
        lbl_803AC668);
    if (result != 0) {
      if (result != 0x11) {
        if ((result != 0x10) && (*(f32 *)((char *)piVar8 + 0x40) < lbl_803E30C0)) {
          kaldaChomFn_8016821c(obj, piVar8);
          *(f32 *)(lbl_803AC668 + 8) = lbl_803E3078;
          *(u16 *)(lbl_803AC668 + 4) = 0;
          *(u16 *)(lbl_803AC668 + 2) = 0;
          *(u16 *)(lbl_803AC668 + 0) = 0;
          (*(void (**)(int, int, void *, int, int, void *))(*(int *)lbl_803DDA90 + 4))(
              0, 1, lbl_803AC668, 0x401, -1, (KaldaCombatParams *)((u8 *)&st + 0xc));
          fn_802961FC(playerObj, 2);
          (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, state, 5);
          objLightFn_8009a1dc(lbl_803E30BC, obj, lbl_803AC668, 4, 0);
          Sfx_PlayFromObject(obj, 0x255);
        }
      }
      else {
        if (*(s16 *)(state + 0x270) != 1) {
          (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, state, 6);
          *(u8 *)(state + 0x27b) = 1;
          *(u8 *)(state + 0x27a) = 1;
          *(s16 *)(state + 0x270) = 1;
          objLightFn_8009a1dc(lbl_803E30BC, obj, lbl_803AC668, 1, 0);
          Sfx_PlayFromObject(obj, SFXen_blkscrp6);
          Sfx_PlayFromObject(obj, 0x3ac);
        }
      }
    }
    if (*(s8 *)(state + 0x354) < 1) {
      *(s16 *)(state + 0x270) = 2;
    }
  }

  if (*(void **)piVar8 != NULL) {
    if (*(f32 *)((char *)piVar8 + 0x40) <= lbl_803E3060) {
      *(u8 *)(*(int *)piVar8 + 0x36) = 0;
      *(f32 *)((char *)piVar8 + 0x40) = lbl_803E3060;
    }
    else {
      rnd = randomGetRange(0, (u8)(s32)*(f32 *)((char *)piVar8 + 0x40));
      *(u8 *)(*(int *)piVar8 + 0x36) = rnd;
      *(s16 *)(*(int *)piVar8 + 4) = *(s16 *)(obj + 4);
      *(s16 *)(*(int *)piVar8 + 2) = *(s16 *)(obj + 2);
      *(s16 *)(*(int *)piVar8 + 0) = *(s16 *)obj;
      *(f32 *)((char *)piVar8 + 0x40) = *(f32 *)((char *)piVar8 + 0x40) - lbl_803E30C4 * timeDelta;
    }
  }
}
#pragma pop

/* Trivial 4b 0-arg blr leaves. */
void kaldachom_func0B(void) {}

/* 8b "li r3, N; blr" returners and small wrappers. */
s16 kaldachom_setScale(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x274); }
int kaldachom_getExtraSize(void) { return 0x45c; }
int kaldachom_getObjectTypeId(void) { return 0x49; }

/*
 * --INFO--
 *
 * Function: kaldachom_free
 * EN v1.0 Address: 0x801692E8
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8016904C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void kaldachom_free(int param_1)
{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,3);
  (*(code *)(*gBaddieControlInterface + 0x40))(param_1,uVar1,0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: kaldachom_render
 * EN v1.0 Address: 0x80169348
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801690A8
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void kaldachom_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
  int state;
  int pathData;
  
  state = *(int *)(obj + 0xb8);
  if ((visible != 0) && (*(int *)(obj + 0xf4) == 0)) {
    if (*(float *)(state + 1000) != lbl_803E3060) {
      fn_8003B5E0(200,0,0,(int)*(float *)(state + 1000));
    }
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
        (obj,p2,p3,p4,p5,lbl_803E3078);
    if ((*(ushort *)(state + 0x400) & 0x60) != 0) {
      objParticleFn_80099d84(obj,lbl_803E3078,3,*(float *)(state + 1000),0);
    }
    pathData = *(int *)(state + 0x40c);
    ObjPath_GetPointWorldPosition(obj,2,pathData + 0x10,pathData + 0x14,pathData + 0x18,0);
    ObjPath_GetPointWorldPosition(obj,1,pathData + 0x28,pathData + 0x2c,pathData + 0x30,0);
  }
  return;
}

void kaldachom_hitDetect(void) {}

/*
 * --INFO--
 *
 * Function: kaldachom_update
 * EN v1.0 Address: 0x80169430
 * EN v1.0 Size: 1120b
 * EN v1.1 Address: 0x801691B8
 * EN v1.1 Size: 940b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void kaldachom_update(int param_1)
{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int *piVar3;
  undefined4 uVar4;
  int iVar8;
  int iVar9;
  f32 dVar10;
  
  iVar9 = *(int *)(param_1 + 0xb8);
  iVar8 = *(int *)(param_1 + 0x4c);
  if (*(int *)(param_1 + 0xf4) != 0) {
    if ((*(short *)(iVar9 + 0x270) != 3) &&
        (iVar1 = (**(code **)(*gMapEventInterface + 0x68))(*(undefined4 *)(iVar8 + 0x14)), iVar1 != 0))
    {
      (**(code **)(*gBaddieControlInterface + 0x58))((double)lbl_803E30C8,param_1,iVar8,iVar9,8,6,0,0x26);
      *(undefined2 *)(iVar9 + 0x402) = 0;
      Sfx_PlayFromObject(param_1,SFXkr_pullup1);
      ObjAnim_SetCurrentMove(param_1,4,lbl_803E3060,0x10);
      *(undefined *)(iVar9 + 0x346) = 0;
      *(undefined *)(param_1 + 0x36) = 0xff;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
  }
  else {
    iVar8 = (**(code **)(*gBaddieControlInterface + 0x30))(param_1,iVar9,0);
    if (iVar8 == 0) {
      *(undefined2 *)(iVar9 + 0x402) = 0;
    }
    else {
      kaldachom_updateCombat(param_1,iVar9,iVar9);
      if (*(short *)(iVar9 + 0x402) == 0) {
        iVar8 = *(int *)(iVar9 + 0x40c);
        *(float *)(iVar8 + 0x34) = *(float *)(iVar8 + 0x34) - timeDelta;
        if (*(float *)(iVar8 + 0x34) <= lbl_803E3060) {
          Sfx_PlayFromObject(param_1,SFXkr_pullup2);
          *(float *)(iVar8 + 0x34) = (f32)(int)randomGetRange(300,600);
        }
        uVar3 = Obj_GetPlayerObject();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar3;
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*gPlayerInterface + 0x30))((double)timeDelta,param_1,iVar9,5);
        }
        iVar8 = (**(code **)(*gBaddieControlInterface + 0x48))
                          ((f64)(f32)(u32)*(u16 *)(iVar9 + 0x3fe),param_1,iVar9,0x8000);
        if (iVar8 != 0) {
          (**(code **)(*gBaddieControlInterface + 0x28))
                    (param_1,iVar9,iVar9 + 0x35c,(int)*(short *)(iVar9 + 0x3f4),0,0,0,4,0xffffffff);
          *(undefined *)(iVar9 + 0x349) = 0;
          *(undefined2 *)(iVar9 + 0x402) = 1;
        }
      }
      else {
        iVar8 = *(int *)(iVar9 + 0x40c);
        piVar3 = (int *)objFindTexture(param_1,0,0);
        *(short *)(iVar8 + 0x48) = *(short *)(iVar8 + 0x48) + 0x1000;
        dVar10 = fn_80293E80((lbl_803E30B4 * (f32)(s32)*(s16 *)(iVar8 + 0x48)) / lbl_803E30B8);
        *piVar3 = (int)(lbl_803E30B0 * (lbl_803E3078 + dVar10));
        uVar3 = Obj_GetPlayerObject();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar3;
        kaldachom_handleAnimEvents(param_1,iVar9,iVar9);
        (**(code **)(*gBaddieControlInterface + 0x2c))((double)lbl_803E3060,param_1,iVar9,0xffffffff);
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*gPlayerInterface + 0x30))((double)timeDelta,param_1,iVar9,5);
        }
        *(undefined4 *)(iVar9 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
        *(undefined4 *)(param_1 + 0xc0) = 0;
        (**(code **)(*gPlayerInterface + 8))
                  ((double)timeDelta,(double)timeDelta,param_1,iVar9,&lbl_803AC698,
                   &lbl_803AC680);
        *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(iVar9 + 0x3e0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: kaldachom_init
 * EN v1.0 Address: 0x801690B8
 * EN v1.0 Size: 488b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void kaldachom_init(int obj, int data, int skip_alloc)
{
  int initMode;
  f32 *pathData;
  int state;
  int player;

  state = *(int *)(obj + 0xb8);
  initMode = 6;
  if (skip_alloc != 0) {
    initMode = 7;
  }
  (**(code **)(*gBaddieControlInterface + 0x58))((double)lbl_803E30C8,obj,data,state,8,6,0,initMode);
  *(undefined4 *)(obj + 0xbc) = 0;
  pathData = *(f32 **)(state + 0x40c);
  ObjAnim_SetCurrentMove(obj,4,lbl_803E3060,0x10);
  *(float *)(obj + 0x98) = lbl_803E307C;
  *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) | 8;
  (**(code **)(*gPlayerInterface + 0x14))(obj,state,0);
  *(undefined2 *)(state + 0x270) = 0;
  *(float *)(state + 0x2a0) = lbl_803E307C;
  *(float *)(state + 0x280) = lbl_803E3060;
  player = Obj_GetPlayerObject();
  *(int *)(state + 0x2d0) = player;
  *(undefined *)(state + 0x25f) = 0;
  ObjHits_DisableObject(obj);
  pathData[0xd] = (f32)(int)randomGetRange(300,600);
  pathData[0xe] = (f32)(int)randomGetRange(0,499);
  pathData[0xf] = lbl_803E3060;
  *(int *)pathData = 0;
  *(ushort *)(obj + 0xb0) = *(ushort *)(obj + 0xb0) | 0x2000;
  *(f32 *)(obj + 8) = lbl_803E30A0 + (f32)(s32)*(s8 *)(data + 0x28) / lbl_803E30A4;
  ObjHitbox_SetSphereRadius(obj,(int)(lbl_803E30CC * *(float *)(obj + 8)));
  if (skip_alloc == 0) {
    lbl_803DDA90 = (undefined4 *)Resource_Acquire(0x5a,1);
  }
  return;
}

void kaldachom_release(void) {}

void kaldachom_initialise(void)
{
  lbl_803AC698[0] = fn_80168118;
  lbl_803AC698[1] = fn_80168018;
  lbl_803AC698[2] = fn_80167F58;
  lbl_803AC698[3] = fn_80167EC4;
  lbl_803AC698[4] = fn_80167E3C;
  lbl_803AC698[5] = fn_80167DA4;
  lbl_803AC698[6] = fn_80167D10;
  lbl_803AC698[7] = fn_80167B60;
  lbl_803AC680[0] = fn_80167AE4;
  lbl_803AC680[1] = fn_80167A60;
  lbl_803AC680[2] = fn_80167988;
  lbl_803AC680[3] = fn_8016792C;
  lbl_803AC680[4] = fn_801678E4;
  lbl_803AC680[5] = fn_80167764;
}

ObjectDescriptor12 gKaldaChomObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)kaldachom_initialise,
    (ObjectDescriptorCallback)kaldachom_release,
    0,
    (ObjectDescriptorCallback)kaldachom_init,
    (ObjectDescriptorCallback)kaldachom_update,
    (ObjectDescriptorCallback)kaldachom_hitDetect,
    (ObjectDescriptorCallback)kaldachom_render,
    (ObjectDescriptorCallback)kaldachom_free,
    (ObjectDescriptorCallback)kaldachom_getObjectTypeId,
    kaldachom_getExtraSize,
    (ObjectDescriptorCallback)kaldachom_setScale,
    (ObjectDescriptorCallback)kaldachom_func0B,
};
