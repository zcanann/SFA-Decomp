#include "ghidra_import.h"
#include "main/dll/campfire.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 Resource_Acquire();
extern uint randomGetRange();
extern undefined4 ObjAnim_SetCurrentMove();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 Obj_IsLoadingLocked();
extern undefined4 Obj_GetPlayerObject();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 FUN_801695e8();
extern undefined8 _savegpr_27();
extern undefined4 _restgpr_27();
extern int FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294c68();

extern undefined4 DAT_802c2990;
extern undefined4 DAT_802c2994;
extern undefined4 DAT_802c2998;
extern undefined4 DAT_802c299c;
extern undefined4 DAT_803ad2c8;
extern undefined4 DAT_803ad2ca;
extern undefined4 DAT_803ad2cc;
extern undefined4 DAT_803ad2d0;
extern undefined4 DAT_803ad2e0;
extern undefined4 DAT_803ad2f8;
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
extern f64 DOUBLE_803E3070;
extern f32 lbl_803E307C;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
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
void fn_8016821C(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int *param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  float *pfVar3;
  int iVar4;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  
  iVar6 = *(int *)(param_9 + 0x4c);
  dVar8 = (double)lbl_803E3D38;
  lbl_803DE714 =
       (float)(dVar8 + (double)((float)((double)CONCAT44(0x43300000,
                                                         (int)*(char *)(iVar6 + 0x28) ^ 0x80000000)
                                       - DOUBLE_803e3d08) / lbl_803E3D3C));
  param_10[0x10] = (int)lbl_803E3D24;
  FUN_80006824(param_9,0x276);
  iVar5 = 0x28;
  do {
    pfVar3 = &lbl_803DE714;
    iVar4 = *pDll_expgfx;
    (**(code **)(iVar4 + 8))(param_9,0x717,0,4,0xffffffff);
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  if ((*param_10 == 0) && (uVar1 = FUN_80017ae8(), (uVar1 & 0xff) != 0)) {
    puVar2 = FUN_80017aa4(0x24,0x55e);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar7 = (double)lbl_803E3D40;
    *(float *)(puVar2 + 6) = (float)(dVar7 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar6 + 4);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar6 + 5);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar6 + 6);
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(iVar6 + 7);
    iVar5 = FUN_80017ae4(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,pfVar3,iVar4,in_r10);
    *param_10 = iVar5;
    *(float *)(*param_10 + 8) = lbl_803DE714;
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
void fn_80168374(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,char param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  iVar4 = *(int *)(param_10 + 0x40c);
  iVar3 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    dVar6 = (double)lbl_803E3D38;
    dVar5 = (double)(float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
                           DOUBLE_803e3d08);
    dVar7 = (double)(float)(dVar6 + (double)(float)(dVar5 / (double)lbl_803E3D3C));
    puVar2 = FUN_80017aa4(0x24,0x51b);
    if (param_11 == '\0') {
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0x28);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x2c);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x30);
    }
    else {
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x14);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x18);
    }
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    iVar3 = FUN_80017ae4(dVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,param_14,param_15,param_16);
    if (iVar3 != 0) {
      dVar5 = (double)(lbl_803E3D44 *
                      (*(float *)(param_10 + 0x2c0) /
                      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x3fe)) -
                             DOUBLE_803e3d00)));
      *(float *)(iVar3 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x2d0) + 0xc) - *(float *)(puVar2 + 4)) /
                  dVar5);
      uVar1 = FUN_80017760(0xfffffff6,10);
      *(float *)(iVar3 + 0x28) =
           (float)((double)(((float)((double)lbl_803E3D40 * dVar7 +
                                    (double)*(float *)(*(int *)(param_10 + 0x2d0) + 0x10)) +
                            (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                   DOUBLE_803e3d08)) - *(float *)(puVar2 + 6)) / dVar5);
      *(float *)(iVar3 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x2d0) + 0x14) - *(float *)(puVar2 + 8))
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
void fn_8016855C(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,int param_15,undefined4 param_16)
{
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
void fn_8016874C(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,int param_11)
{
  float fVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  double dVar8;
  undefined8 uVar9;
  undefined auStack_48 [2];
  undefined auStack_46 [2];
  short local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  longlong local_20;
  
  uVar9 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  piVar7 = *(int **)(iVar6 + 0x40c);
  local_34 = DAT_802c2990;
  local_30 = DAT_802c2994;
  local_2c = DAT_802c2998;
  local_28 = DAT_802c299c;
  uVar3 = FUN_80017a98();
  iVar4 = *(int *)(param_11 + 0x2d0);
  if (iVar4 != 0) {
    local_40 = *(float *)(iVar4 + 0x18) - *(float *)(puVar2 + 0xc);
    param_4 = (double)local_40;
    local_3c = *(float *)(iVar4 + 0x1c) - *(float *)(puVar2 + 0xe);
    param_3 = (double)local_3c;
    local_38 = *(float *)(iVar4 + 0x20) - *(float *)(puVar2 + 0x10);
    param_2 = (double)(local_38 * local_38);
    dVar8 = FUN_80293900((double)(float)(param_2 +
                                        (double)((float)(param_4 * param_4) +
                                                (float)(param_3 * param_3))));
    *(float *)(param_11 + 0x2c0) = (float)dVar8;
  }
  (**(code **)(*lbl_803DCAB8 + 0x54))
            (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,0,4);
  (**(code **)(*lbl_803DCAB8 + 0x14))(puVar2,uVar3,4,local_44,auStack_46,auStack_48);
  if ((local_44[0] == 1) || (local_44[0] == 2)) {
    iVar4 = (**(code **)(*lbl_803DCAB8 + 0x50))
                      (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar4 != 0) {
      if ((iVar4 != 0x10) && (iVar4 != 0x11)) {
        FUN_80081120(puVar2,&DAT_803ad2c8,3,(int *)0x0);
        (**(code **)(*lbl_803DCA8C + 0x14))(puVar2,param_11,4);
        *(char *)(param_11 + 0x354) = *(char *)(param_11 + 0x354) + -1;
        FUN_80017a28(puVar2,0xf,200,0,0,1);
        FUN_80006824((uint)puVar2,0x22);
      }
      if (*(char *)(param_11 + 0x354) < '\x01') {
        *(undefined2 *)(param_11 + 0x270) = 2;
      }
    }
  }
  else {
    iVar4 = (**(code **)(*lbl_803DCAB8 + 0x50))
                      (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar4 != 0) {
      if (iVar4 == 0x11) {
        if (*(short *)(param_11 + 0x270) != 1) {
          (**(code **)(*lbl_803DCA8C + 0x14))(puVar2,param_11,6);
          *(undefined *)(param_11 + 0x27b) = 1;
          *(undefined *)(param_11 + 0x27a) = 1;
          *(undefined2 *)(param_11 + 0x270) = 1;
          FUN_80081120(puVar2,&DAT_803ad2c8,1,(int *)0x0);
          FUN_80006824((uint)puVar2,0x22);
          FUN_80006824((uint)puVar2,0x3ac);
        }
      }
      else if ((iVar4 != 0x10) && ((double)(float)piVar7[0x10] < (double)lbl_803E3D58)) {
        fn_8016821C((double)(float)piVar7[0x10],param_2,param_3,param_4,param_5,param_6,param_7,
                     param_8,(uint)puVar2,piVar7);
        DAT_803ad2d0 = lbl_803E3D10;
        DAT_803ad2cc = 0;
        DAT_803ad2ca = 0;
        DAT_803ad2c8 = 0;
        (**(code **)(*lbl_803DDA90 + 4))(0,1,&DAT_803ad2c8,0x401,0xffffffff,&local_34);
        FUN_80294c68(uVar3,2);
        (**(code **)(*lbl_803DCA8C + 0x14))(puVar2,param_11,5);
        FUN_80081120(puVar2,&DAT_803ad2c8,4,(int *)0x0);
        FUN_80006824((uint)puVar2,0x255);
      }
    }
    if (*(char *)(param_11 + 0x354) < '\x01') {
      *(undefined2 *)(param_11 + 0x270) = 2;
    }
  }
  fVar1 = lbl_803E3CF8;
  if (*piVar7 != 0) {
    if (lbl_803E3CF8 < (float)piVar7[0x10]) {
      uVar5 = (uint)(float)piVar7[0x10];
      local_20 = (longlong)(int)uVar5;
      uVar5 = FUN_80017760(0,uVar5 & 0xff);
      *(char *)(*piVar7 + 0x36) = (char)uVar5;
      *(undefined2 *)(*piVar7 + 4) = puVar2[2];
      *(undefined2 *)(*piVar7 + 2) = puVar2[1];
      *(undefined2 *)*piVar7 = *puVar2;
      piVar7[0x10] = (int)-(lbl_803E3D5C * lbl_803DC074 - (float)piVar7[0x10]);
    }
    else {
      *(undefined *)(*piVar7 + 0x36) = 0;
      piVar7[0x10] = (int)fVar1;
    }
  }
  FUN_8028688c();
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
  (**(code **)(*lbl_803DCAB8 + 0x40))(param_1,uVar1,0x20);
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
void kaldachom_render(void)
{
  int iVar1;
  char in_r8;
  int iVar2;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if (*(float *)(iVar2 + 1000) != lbl_803E3CF8) {
      FUN_8003b540(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b818(iVar1);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8008111c((double)lbl_803E3D10,(double)*(float *)(iVar2 + 1000),iVar1,3,(int *)0x0);
    }
    iVar2 = *(int *)(iVar2 + 0x40c);
    ObjPath_GetPointWorldPosition(iVar1,2,(float *)(iVar2 + 0x10),(undefined4 *)(iVar2 + 0x14),
                 (float *)(iVar2 + 0x18),0);
    ObjPath_GetPointWorldPosition(iVar1,1,(float *)(iVar2 + 0x28),(undefined4 *)(iVar2 + 0x2c),
                 (float *)(iVar2 + 0x30),0);
  }
  FUN_80286888();
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
void kaldachom_update(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9)
{
  int iVar1;
  uint uVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 in_r7;
  undefined4 uVar5;
  int in_r8;
  undefined4 uVar6;
  int in_r9;
  undefined4 uVar7;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  double dVar10;
  double dVar11;
  
  iVar9 = *(int *)(param_9 + 0xb8);
  iVar8 = *(int *)(param_9 + 0x4c);
  if (*(int *)(param_9 + 0xf4) == 0) {
    iVar1 = *lbl_803DCAB8;
    iVar8 = (**(code **)(iVar1 + 0x30))(param_9,iVar9,0);
    if (iVar8 == 0) {
      *(undefined2 *)(iVar9 + 0x402) = 0;
    }
    else {
      fn_8016874C(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar9
                   ,iVar9);
      if (*(short *)(iVar9 + 0x402) == 0) {
        iVar8 = *(int *)(iVar9 + 0x40c);
        *(float *)(iVar8 + 0x34) = *(float *)(iVar8 + 0x34) - lbl_803DC074;
        if (*(float *)(iVar8 + 0x34) <= lbl_803E3CF8) {
          FUN_80006824(param_9,0x271);
          uVar2 = FUN_80017760(300,600);
          *(float *)(iVar8 + 0x34) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3d08);
        }
        uVar4 = FUN_80017a98();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar4;
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*lbl_803DCA8C + 0x30))((double)lbl_803DC074,param_9,iVar9,5);
        }
        iVar8 = (**(code **)(*lbl_803DCAB8 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar9 + 0x3fe)) -
                                          DOUBLE_803e3d00),param_9,iVar9,0x8000);
        if (iVar8 != 0) {
          (**(code **)(*lbl_803DCAB8 + 0x28))
                    (param_9,iVar9,iVar9 + 0x35c,(int)*(short *)(iVar9 + 0x3f4),0,0,0,4,0xffffffff);
          *(undefined *)(iVar9 + 0x349) = 0;
          *(undefined2 *)(iVar9 + 0x402) = 1;
        }
      }
      else {
        iVar8 = *(int *)(iVar9 + 0x40c);
        piVar3 = (int *)FUN_80039520(param_9,0);
        *(short *)(iVar8 + 0x48) = *(short *)(iVar8 + 0x48) + 0x1000;
        dVar11 = (double)lbl_803E3D4C;
        dVar10 = (double)FUN_80293f90();
        dVar10 = (double)(float)((double)lbl_803E3D10 + dVar10);
        *piVar3 = (int)((double)lbl_803E3D48 * dVar10);
        uVar4 = FUN_80017a98();
        *(undefined4 *)(iVar9 + 0x2d0) = uVar4;
        fn_8016855C(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar9,
                     iVar9,iVar1,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*lbl_803DCAB8 + 0x2c))((double)lbl_803E3CF8,param_9,iVar9,0xffffffff);
        if (*(short *)(iVar9 + 0x274) != 6) {
          (**(code **)(*lbl_803DCA8C + 0x30))((double)lbl_803DC074,param_9,iVar9,5);
        }
        *(undefined4 *)(iVar9 + 0x3e0) = *(undefined4 *)(param_9 + 0xc0);
        *(undefined4 *)(param_9 + 0xc0) = 0;
        (**(code **)(*lbl_803DCA8C + 8))
                  ((double)lbl_803DC074,(double)lbl_803DC074,param_9,iVar9,&DAT_803ad2f8,
                   &DAT_803ad2e0);
        *(undefined4 *)(param_9 + 0xc0) = *(undefined4 *)(iVar9 + 0x3e0);
      }
    }
  }
  else if ((*(short *)(iVar9 + 0x270) != 3) &&
          (iVar1 = (**(code **)(*lbl_803DCAAC + 0x68))(*(undefined4 *)(iVar8 + 0x14)), iVar1 != 0))
  {
    uVar4 = 8;
    uVar5 = 6;
    uVar6 = 0;
    uVar7 = 0x26;
    iVar1 = *lbl_803DCAB8;
    (**(code **)(iVar1 + 0x58))((double)lbl_803E3D60,param_9,iVar8,iVar9);
    *(undefined2 *)(iVar9 + 0x402) = 0;
    FUN_80006824(param_9,0x270);
    FUN_800305f8((double)lbl_803E3CF8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0x10,uVar4,uVar5,uVar6,uVar7,iVar1);
    *(undefined *)(iVar9 + 0x346) = 0;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
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
