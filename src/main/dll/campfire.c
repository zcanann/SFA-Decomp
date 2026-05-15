#include "ghidra_import.h"
#include "main/dll/campfire.h"

extern undefined4 FUN_80006824();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 Resource_Acquire();
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjAnim_SetCurrentMove();
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject();
extern undefined4 Obj_SetModelColorFadeRecursive();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 Obj_IsLoadingLocked();
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
extern undefined8 _savegpr_27();
extern undefined4 _restgpr_27();
extern undefined8 _savegpr_26();
extern undefined4 _restgpr_26();
extern int FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double sqrtf();
extern double FUN_80293900();
extern double fn_80293E80();
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
extern undefined4* pDll_expgfx;
extern undefined4* lbl_803DCA8C;
extern undefined4* lbl_803DCAAC;
extern undefined4* lbl_803DCAB8;
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
 * Function: fn_8016821C
 * EN v1.0 Address: 0x80168818
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x801686C8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8016821C(int param_1,int *param_2)
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
  Sfx_PlayFromObject(param_1,0x276);
  iVar2 = 0x28;
  do {
    (**(code **)(*pDll_expgfx + 8))(param_1,0x717,0,4,0xffffffff,&lbl_803DDA94);
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

/*
 * --INFO--
 *
 * Function: fn_80168374
 * EN v1.0 Address: 0x80168A0C
 * EN v1.0 Size: 640b
 * EN v1.1 Address: 0x80168820
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80168374(int param_1,int param_2,char param_3)
{
  uint uVar1;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;

  iVar4 = *(int *)(param_2 + 0x40c);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((char)Obj_IsLoadingLocked() != '\0') {
    dVar6 = (double)(lbl_803E30A0 +
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
                           DOUBLE_803E3070) / lbl_803E30A4);
    iVar3 = Obj_AllocObjectSetup(0x24,0x51b);
    if (param_3 == '\0') {
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 0x28);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0x2c);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0x30);
    }
    else {
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0x14);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0x18);
    }
    *(undefined *)(iVar3 + 4) = 1;
    *(undefined *)(iVar3 + 5) = 4;
    *(undefined *)(iVar3 + 6) = 0xff;
    *(undefined *)(iVar3 + 7) = 0xff;
    iVar4 = Obj_SetupObject(iVar3,5,0xffffffff,0xffffffff,0);
    if (iVar4 != 0) {
      dVar7 = (double)(lbl_803E30AC *
                      (*(float *)(param_2 + 0x2c0) /
                      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3fe)) -
                             lbl_803E3068)));
      dVar5 = dVar7;
      *(float *)(iVar4 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_2 + 0x2d0) + 0xc) - *(float *)(iVar3 + 8)) /
                  dVar5);
      uVar1 = randomGetRange(0xfffffff6,10);
      *(float *)(iVar4 + 0x28) =
           (float)((double)(((float)((double)lbl_803E30A8 * dVar6 +
                                    (double)*(float *)(*(int *)(param_2 + 0x2d0) + 0x10)) +
                            (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                   DOUBLE_803E3070)) - *(float *)(iVar3 + 0xc)) / dVar5);
      *(float *)(iVar4 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_2 + 0x2d0) + 0x14) - *(float *)(iVar3 + 0x10))
                  / dVar5);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8016855C
 * EN v1.0 Address: 0x80168C8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80168A08
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8016855C(undefined4 param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;

  uVar6 = _savegpr_27();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar4 = (int)uVar6;
  iVar5 = *(int *)(iVar4 + 0x40c);
  lbl_803DDA98 =
       lbl_803E30A0 +
       (float)((double)CONCAT44(0x43300000,
                                (int)*(char *)(*(int *)(iVar1 + 0x4c) + 0x28) ^ 0x80000000) -
              DOUBLE_803E3070) / lbl_803E30A4;
  if ((*(uint *)(param_3 + 0x314) & 1) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffffe;
    Sfx_PlayFromObject(iVar1,0x273);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x80) != 0) {
    uVar2 = randomGetRange(0,2);
    *(undefined *)(iVar5 + 0x4a) = uVar2;
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xffffff7f;
    Sfx_PlayFromObject(iVar1,0x274);
    for (iVar3 = (2 - (uint)*(byte *)(iVar5 + 0x4a)) * 10; iVar3 != 0; iVar3 = iVar3 + -1) {
      (**(code **)(*pDll_expgfx + 8))(iVar1,0x711,0,4,0xffffffff,&lbl_803DDA98);
    }
  }
  if ((*(uint *)(param_3 + 0x314) & 0x40) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xffffffbf;
    fn_80168374(iVar1,iVar4,0);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x800) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffff7ff;
    fn_80168374(iVar1,iVar4,1);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffdff;
    Sfx_PlayFromObject(iVar1,0x275);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x400) != 0) {
    *(undefined *)(iVar5 + 0x4a) = 3;
    iVar4 = 10;
    do {
      (**(code **)(*pDll_expgfx + 8))(iVar1,0x710,0,4,0xffffffff,&lbl_803DDA98);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffbff;
  }
  _restgpr_27();
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8016874C
 * EN v1.0 Address: 0x80168C90
 * EN v1.0 Size: 1624b
 * EN v1.1 Address: 0x80168BF8
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8016874C(undefined4 param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  float fVar1;
  undefined2 *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined uVar6;
  int iVar7;
  int *piVar8;
  double dVar8;
  undefined8 uVar10;
  undefined auStack72 [2];
  undefined auStack70 [2];
  short local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  longlong local_20;
  
  uVar10 = _savegpr_27();
  puVar3 = (undefined2 *)((ulonglong)uVar10 >> 0x20);
  iVar7 = (int)uVar10;
  piVar8 = *(int **)(iVar7 + 0x40c);
  local_34 = lbl_802C2210[0];
  local_30 = lbl_802C2210[1];
  local_2c = lbl_802C2210[2];
  local_28 = lbl_802C2210[3];
  uVar4 = Obj_GetPlayerObject();
  iVar5 = *(int *)(param_3 + 0x2d0);
  if (iVar5 != 0) {
    local_40 = *(float *)(iVar5 + 0x18) - *(float *)(puVar3 + 0xc);
    local_3c = *(float *)(iVar5 + 0x1c) - *(float *)(puVar3 + 0xe);
    local_38 = *(float *)(iVar5 + 0x20) - *(float *)(puVar3 + 0x10);
    dVar8 = (double)sqrtf((double)(local_38 * local_38 + local_40 * local_40 + local_3c * local_3c));
    *(float *)(param_3 + 0x2c0) = (float)dVar8;
  }
  (**(code **)(*lbl_803DCAB8 + 0x54))
            (puVar3,param_3,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,0,4);
  (**(code **)(*lbl_803DCAB8 + 0x14))(puVar3,uVar4,4,local_44,auStack70,auStack72);
  if ((local_44[0] == 1) || (local_44[0] == 2)) {
    iVar5 = (**(code **)(*lbl_803DCAB8 + 0x50))
                      (puVar3,param_3,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar5 != 0) {
      if ((iVar5 != 0x10) && (iVar5 != 0x11)) {
        objLightFn_8009a1dc((double)lbl_803E30BC,puVar3,&DAT_803ad2c8,3,0);
        (**(code **)(*lbl_803DCA8C + 0x14))(puVar3,param_3,4);
        *(char *)(param_3 + 0x354) = *(char *)(param_3 + 0x354) + -1;
        Obj_SetModelColorFadeRecursive(puVar3,0xf,200,0,0,1);
        Sfx_PlayFromObject((uint)puVar3,0x22);
      }
      if (*(char *)(param_3 + 0x354) < '\x01') {
        *(undefined2 *)(param_3 + 0x270) = 2;
      }
    }
  }
  else {
    iVar5 = (**(code **)(*lbl_803DCAB8 + 0x50))
                      (puVar3,param_3,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar5 != 0) {
      if (iVar5 == 0x11) {
        if (*(short *)(param_3 + 0x270) != 1) {
          (**(code **)(*lbl_803DCA8C + 0x14))(puVar3,param_3,6);
          *(undefined *)(param_3 + 0x27b) = 1;
          *(undefined *)(param_3 + 0x27a) = 1;
          *(undefined2 *)(param_3 + 0x270) = 1;
          objLightFn_8009a1dc((double)lbl_803E30BC,puVar3,&DAT_803ad2c8,1,0);
          Sfx_PlayFromObject((uint)puVar3,0x22);
          Sfx_PlayFromObject((uint)puVar3,0x3ac);
        }
      }
      else if ((iVar5 != 0x10) && ((float)piVar8[0x10] < lbl_803E30C0)) {
        fn_8016821C((int)puVar3,piVar8);
        DAT_803ad2d0 = lbl_803E3078;
        DAT_803ad2cc = 0;
        DAT_803ad2ca = 0;
        DAT_803ad2c8 = 0;
        (**(code **)(*lbl_803DDA90 + 4))(0,1,&DAT_803ad2c8,0x401,0xffffffff,&local_34);
        fn_802961FC(uVar4,2);
        (**(code **)(*lbl_803DCA8C + 0x14))(puVar3,param_3,5);
        objLightFn_8009a1dc((double)lbl_803E30BC,puVar3,&DAT_803ad2c8,4,0);
        Sfx_PlayFromObject((uint)puVar3,0x255);
      }
    }
    if (*(char *)(param_3 + 0x354) < '\x01') {
      *(undefined2 *)(param_3 + 0x270) = 2;
    }
  }
  fVar1 = lbl_803E3060;
  if (*piVar8 != 0) {
    if (lbl_803E3060 < (float)piVar8[0x10]) {
      uVar1 = (uint)(float)piVar8[0x10];
      local_20 = (longlong)(int)uVar1;
      uVar6 = randomGetRange(0,uVar1 & 0xff);
      *(undefined *)(*piVar8 + 0x36) = uVar6;
      *(undefined2 *)(*piVar8 + 4) = puVar3[2];
      *(undefined2 *)(*piVar8 + 2) = puVar3[1];
      *(undefined2 *)*piVar8 = *puVar3;
      piVar8[0x10] = (int)-(lbl_803E30C4 * timeDelta - (float)piVar8[0x10]);
    }
    else {
      *(undefined *)(*piVar8 + 0x36) = 0;
      piVar8[0x10] = (int)fVar1;
    }
  }
  _restgpr_27();
  return;
}

/* Trivial 4b 0-arg blr leaves. */
void kaldachom_func0B(void) {}

/* 8b "li r3, N; blr" returners and small wrappers. */
s16 kaldachom_setScale(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x274); }
int kaldachom_getExtraSize(void) { return 0x45c; }
int kaldachom_func08(void) { return 0x49; }

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
  (*(code *)(*lbl_803DCAB8 + 0x40))(param_1,uVar1,0x20);
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
void kaldachom_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                      undefined4 param_5,char param_6)
{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = _savegpr_26();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((param_6 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if (*(float *)(iVar2 + 1000) != lbl_803E3060) {
      fn_8003B5E0(200,0,0,(int)*(float *)(iVar2 + 1000));
    }
    objRenderFn_8003b8f4((double)lbl_803E3078,iVar1,(int)uVar3,param_3,param_4,param_5);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      objParticleFn_80099d84((double)lbl_803E3078,(double)*(float *)(iVar2 + 1000),iVar1,3,0);
    }
    iVar2 = *(int *)(iVar2 + 0x40c);
    ObjPath_GetPointWorldPosition(iVar1,2,iVar2 + 0x10,iVar2 + 0x14,iVar2 + 0x18,0);
    ObjPath_GetPointWorldPosition(iVar1,1,iVar2 + 0x28,iVar2 + 0x2c,iVar2 + 0x30,0);
  }
  _restgpr_26();
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
  double dVar10;
  
  iVar9 = *(int *)(param_1 + 0xb8);
  iVar8 = *(int *)(param_1 + 0x4c);
  if (*(int *)(param_1 + 0xf4) == 0) {
    iVar8 = (**(code **)(*lbl_803DCAB8 + 0x30))(param_1,iVar9,0);
    if (iVar8 == 0) {
      *(undefined2 *)(iVar9 + 0x402) = 0;
    }
    else {
      fn_8016874C(param_1,iVar9,iVar9);
      if (*(short *)(iVar9 + 0x402) == 0) {
        iVar8 = *(int *)(iVar9 + 0x40c);
        *(float *)(iVar8 + 0x34) = *(float *)(iVar8 + 0x34) - timeDelta;
        if (*(float *)(iVar8 + 0x34) <= lbl_803E3060) {
          Sfx_PlayFromObject(param_1,0x271);
          uVar2 = randomGetRange(300,600);
          *(float *)(iVar8 + 0x34) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803E3070);
        }
        uVar3 = Obj_GetPlayerObject();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar3;
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*lbl_803DCA8C + 0x30))((double)timeDelta,param_1,iVar9,5);
        }
        iVar8 = (**(code **)(*lbl_803DCAB8 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar9 + 0x3fe)) -
                                          lbl_803E3068),param_1,iVar9,0x8000);
        if (iVar8 != 0) {
          (**(code **)(*lbl_803DCAB8 + 0x28))
                    (param_1,iVar9,iVar9 + 0x35c,(int)*(short *)(iVar9 + 0x3f4),0,0,0,4,0xffffffff);
          *(undefined *)(iVar9 + 0x349) = 0;
          *(undefined2 *)(iVar9 + 0x402) = 1;
        }
      }
      else {
        iVar8 = *(int *)(iVar9 + 0x40c);
        piVar3 = (int *)objFindTexture(param_1,0,0);
        *(short *)(iVar8 + 0x48) = *(short *)(iVar8 + 0x48) + 0x1000;
        dVar10 = (double)fn_80293E80((double)((lbl_803E30B4 *
                                              (float)((double)CONCAT44(0x43300000,
                                                                       (int)*(short *)(iVar8 + 0x48)
                                                                       ^ 0x80000000) -
                                                     DOUBLE_803E3070)) / lbl_803E30B8));
        *piVar3 = (int)(lbl_803E30B0 * (float)((double)lbl_803E3078 + dVar10));
        uVar3 = Obj_GetPlayerObject();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar3;
        fn_8016855C(param_1,iVar9,iVar9);
        (**(code **)(*lbl_803DCAB8 + 0x2c))((double)lbl_803E3060,param_1,iVar9,0xffffffff);
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*lbl_803DCA8C + 0x30))((double)timeDelta,param_1,iVar9,5);
        }
        *(undefined4 *)(iVar9 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
        *(undefined4 *)(param_1 + 0xc0) = 0;
        (**(code **)(*lbl_803DCA8C + 8))
                  ((double)timeDelta,(double)timeDelta,param_1,iVar9,&lbl_803AC698,
                   &lbl_803AC680);
        *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(iVar9 + 0x3e0);
      }
    }
  }
  else if ((*(short *)(iVar9 + 0x270) != 3) &&
          (iVar1 = (**(code **)(*lbl_803DCAAC + 0x68))(*(undefined4 *)(iVar8 + 0x14)), iVar1 != 0))
  {
    (**(code **)(*lbl_803DCAB8 + 0x58))((double)lbl_803E30C8,param_1,iVar8,iVar9,8,6,0,0x26);
    *(undefined2 *)(iVar9 + 0x402) = 0;
    Sfx_PlayFromObject(param_1,0x270);
    ObjAnim_SetCurrentMove((double)lbl_803E3060,param_1,4,0x10);
    *(undefined *)(iVar9 + 0x346) = 0;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
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
void kaldachom_init(undefined4 param_1,undefined4 param_2,int param_3)
{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined8 uVar7;

  uVar7 = _savegpr_27();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  iVar6 = *(int *)(iVar2 + 0xb8);
  uVar4 = 6;
  if (param_3 != 0) {
    uVar4 = 7;
  }
  (**(code **)(*lbl_803DCAB8 + 0x58))((double)lbl_803E30C8,iVar2,(int)uVar7,iVar6,8,6,0,uVar4);
  *(undefined4 *)(iVar2 + 0xbc) = 0;
  puVar5 = *(undefined4 **)(iVar6 + 0x40c);
  ObjAnim_SetCurrentMove((double)lbl_803E3060,iVar2,4,0x10);
  *(float *)(iVar2 + 0x98) = lbl_803E307C;
  *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
  (**(code **)(*lbl_803DCA8C + 0x14))(iVar2,iVar6,0);
  *(undefined2 *)(iVar6 + 0x270) = 0;
  *(float *)(iVar6 + 0x2a0) = lbl_803E307C;
  *(float *)(iVar6 + 0x280) = lbl_803E3060;
  uVar4 = Obj_GetPlayerObject();
  *(undefined4 *)(iVar6 + 0x2d0) = uVar4;
  *(undefined *)(iVar6 + 0x25f) = 0;
  ObjHits_DisableObject(iVar2);
  uVar3 = randomGetRange(300,600);
  puVar5[0xd] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803E3070);
  uVar3 = randomGetRange(0,499);
  dVar1 = DOUBLE_803E3070;
  puVar5[0xe] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803E3070);
  puVar5[0xf] = lbl_803E3060;
  *puVar5 = 0;
  *(ushort *)(iVar2 + 0xb0) = *(ushort *)(iVar2 + 0xb0) | 0x2000;
  *(float *)(iVar2 + 8) =
       lbl_803E30A0 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)((int)uVar7 + 0x28) ^ 0x80000000) - dVar1)
       / lbl_803E30A4;
  ObjHitbox_SetSphereRadius(iVar2,(int)(lbl_803E30CC * *(float *)(iVar2 + 8)));
  if (param_3 == 0) {
    lbl_803DDA90 = (undefined4 *)Resource_Acquire(0x5a,1);
  }
  _restgpr_27();
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
