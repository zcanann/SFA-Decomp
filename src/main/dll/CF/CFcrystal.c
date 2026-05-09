#include "ghidra_import.h"
#include "main/dll/CF/CFcrystal.h"

extern undefined4 FUN_800068c4();
extern double FUN_80006a38();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017680();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80061a80();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803de758;
extern f64 DOUBLE_803e4748;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dca40;
extern f32 FLOAT_803e4724;
extern f32 FLOAT_803e4728;
extern f32 FLOAT_803e4730;
extern f32 FLOAT_803e4734;
extern f32 FLOAT_803e4738;
extern f32 FLOAT_803e473c;
extern f32 FLOAT_803e4740;
extern f32 FLOAT_803e4750;
extern f32 FLOAT_803e4754;
extern f32 FLOAT_803e4758;
extern f32 FLOAT_803e475c;
extern f32 FLOAT_803e4760;
extern f32 FLOAT_803e476c;

/*
 * --INFO--
 *
 * Function: FUN_80186b94
 * EN v1.0 Address: 0x80186B94
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80186BA4
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80186b94(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = (short)((int)*(short *)(param_2 + 0x1c) << 8);
  *(float *)(param_1 + 4) = FLOAT_803e4724;
  *(float *)(iVar2 + 4) = *(float *)(param_1 + 0x54) * *(float *)(param_1 + 4) * FLOAT_803e4728;
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    param_1[3] = param_1[3] | 0x4000;
    param_1[0x58] = param_1[0x58] | 0xe000;
  }
  *(undefined4 *)(iVar2 + 8) = 0xffffffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80186c34
 * EN v1.0 Address: 0x80186C34
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x80186C70
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80186c34(short *param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  iVar6 = *(int *)(param_1 + 0x26);
  *(short *)(iVar7 + 0x68) = (short)*(char *)(iVar6 + 0x18);
  *(undefined *)(iVar7 + 0x6a) = *(undefined *)(iVar6 + 0x19);
  *(float *)(iVar7 + 0x4c) = FLOAT_803e4738;
  *(float *)(iVar7 + 0x50) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
              DOUBLE_803e4748);
  *(undefined *)(iVar7 + 0x6f) = 0;
  FUN_80061a80(param_1,(short *)0x0,1);
  iVar5 = FUN_80017a98();
  fVar1 = *(float *)(iVar5 + 0x18);
  fVar2 = *(float *)(iVar5 + 0x20);
  fVar3 = *(float *)(iVar5 + 0x1c) + FLOAT_803e473c;
  fVar4 = FLOAT_803e4740 + *(float *)(iVar5 + 0x1c);
  iVar5 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar5 + 0x54) = fVar1;
  *(float *)(iVar5 + 0x58) = fVar4;
  *(float *)(iVar5 + 0x5c) = fVar2;
  iVar5 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar5 + 0x34) = fVar1 - *(float *)(iVar5 + 0x54);
  *(float *)(iVar5 + 0x38) = fVar3 - *(float *)(iVar5 + 0x58);
  *(float *)(iVar5 + 0x3c) = fVar2 - *(float *)(iVar5 + 0x5c);
  *(undefined *)(iVar5 + 0x6c) = 4;
  FUN_80186e70((int)param_1);
  FUN_80186e70((int)param_1);
  FUN_80186e70((int)param_1);
  FUN_80186e70((int)param_1);
  FUN_80186e70((int)param_1);
  FUN_80186e70((int)param_1);
  *(byte *)(iVar7 + 0x70) = *(byte *)(iVar7 + 0x70) & 0x3f | 0x40;
  *(int *)(iVar7 + 0x60) = (int)*(short *)(iVar6 + 0x1a);
  FUN_80017688(0x698);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80186d78
 * EN v1.0 Address: 0x80186D78
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80186E28
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80186d78(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined8 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar3 + 0x34) = FLOAT_803e4750;
  uVar2 = FUN_80017760(-(int)*(short *)(iVar3 + 0x68),(int)*(short *)(iVar3 + 0x68));
  local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
  *(float *)(iVar3 + 0x38) = (float)(local_20 - DOUBLE_803e4748);
  if (FLOAT_803e4754 <= *(float *)(iVar3 + 0x50)) {
    iVar1 = (int)*(float *)(iVar3 + 0x50);
    local_20 = (double)(longlong)iVar1;
    uStack_14 = FUN_80017760(0x14,(int)(short)iVar1);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(iVar3 + 0x3c) =
         *(float *)(iVar3 + 0x50) -
         (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4748);
  }
  else {
    *(float *)(iVar3 + 0x3c) = FLOAT_803e4750;
  }
  uVar2 = FUN_80017760(3000,5000);
  *(short *)(iVar3 + 100) = *(short *)(iVar3 + 100) + (short)uVar2;
  local_2c = FLOAT_803e4750;
  local_28 = FLOAT_803e4750;
  local_24 = FLOAT_803e4750;
  local_30 = FLOAT_803e4738;
  local_38[2] = 0;
  local_38[1] = 0;
  local_38[0] = *(ushort *)(iVar3 + 100);
  FUN_80017748(local_38,(float *)(iVar3 + 0x34));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80186e70
 * EN v1.0 Address: 0x80186E70
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x80186F34
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80186e70(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar3 + 4) = *(undefined4 *)(iVar3 + 8);
  *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar3 + 0x18);
  *(undefined4 *)(iVar3 + 0x24) = *(undefined4 *)(iVar3 + 0x28);
  *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar3 + 0xc);
  *(undefined4 *)(iVar3 + 0x18) = *(undefined4 *)(iVar3 + 0x1c);
  *(undefined4 *)(iVar3 + 0x28) = *(undefined4 *)(iVar3 + 0x2c);
  *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar3 + 0x10);
  *(undefined4 *)(iVar3 + 0x1c) = *(undefined4 *)(iVar3 + 0x20);
  *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(iVar3 + 0x30);
  if (*(byte *)(iVar3 + 0x70) >> 6 == 1) {
    iVar1 = FUN_80017a98();
    dVar4 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
    *(float *)(iVar3 + 0x44) = (float)((double)FLOAT_803e475c * dVar4 + (double)FLOAT_803e4758);
  }
  else {
    uVar2 = FUN_80017760(0x3c,0x5a);
    *(float *)(iVar3 + 0x44) =
         FLOAT_803e475c * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4748)
    ;
  }
  *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar3 + 0x34);
  *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(iVar3 + 0x38);
  *(undefined4 *)(iVar3 + 0x30) = *(undefined4 *)(iVar3 + 0x3c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80186f88
 * EN v1.0 Address: 0x80186F88
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80187044
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80186f88(int param_1,int param_2)
{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  if (*puVar1 != 0) {
    FUN_80017620(*puVar1);
    *puVar1 = 0;
  }
  if (((param_2 == 0) && (*puVar1 != 0)) && (*(byte *)(puVar1 + 0x1c) >> 6 != 1)) {
    DAT_803de758 = 0;
  }
  ObjGroup_RemoveObject(param_1,0x30);
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80187034
 * EN v1.0 Address: 0x80187034
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801870EC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80187034(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018705c
 * EN v1.0 Address: 0x8018705C
 * EN v1.0 Size: 2132b
 * EN v1.1 Address: 0x80187120
 * EN v1.1 Size: 1256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018705c(uint param_1)
{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  undefined4 in_r10;
  int *piVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float fVar12;
  float fVar13;
  float fVar14;
  undefined8 local_38;
  
  piVar7 = *(int **)(param_1 + 0xb8);
  iVar3 = FUN_80017a98();
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  if (FLOAT_803e4738 < (float)piVar7[0x10]) {
    piVar7[0x10] = (int)((float)piVar7[0x10] - FLOAT_803e4738);
    bVar1 = *(byte *)(piVar7 + 0x1b);
    if (bVar1 < 4) {
      FUN_80186d78(param_1);
    }
    else if (bVar1 == 7) {
      *(undefined *)(piVar7 + 0x1b) = 0;
    }
    else {
      *(byte *)(piVar7 + 0x1b) = bVar1 + 1;
    }
    FUN_80186e70(param_1);
  }
  dVar8 = FUN_80006a38((double)(float)piVar7[0x10],(float *)(piVar7 + 1),(float *)0x0);
  *(float *)(param_1 + 0xc) = (float)((double)(float)piVar7[0x15] + dVar8);
  dVar8 = FUN_80006a38((double)(float)piVar7[0x10],(float *)(piVar7 + 5),(float *)0x0);
  *(float *)(param_1 + 0x10) = (float)((double)(float)piVar7[0x16] + dVar8);
  dVar8 = FUN_80006a38((double)(float)piVar7[0x10],(float *)(piVar7 + 9),(float *)0x0);
  *(float *)(param_1 + 0x14) = (float)((double)(float)piVar7[0x17] + dVar8);
  if (*(byte *)(piVar7 + 0x1c) >> 6 == 1) {
    iVar4 = FUN_80017a98();
    dVar8 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
    piVar7[0x11] = (int)(float)((double)FLOAT_803e475c * dVar8 + (double)FLOAT_803e4758);
  }
  piVar7[0x10] = (int)((float)piVar7[0x11] * FLOAT_803dc074 + (float)piVar7[0x10]);
  if ((((*(char *)((int)piVar7 + 0x6a) == '\x01') || (*(char *)((int)piVar7 + 0x6a) == '\x04')) &&
      (*(byte *)(piVar7 + 0x1c) >> 6 == 1)) && (*(char *)((int)piVar7 + 0x6e) == '\0')) {
    *(undefined *)((int)piVar7 + 0x6e) = 1;
    piVar5 = FUN_80017624(param_1,'\x01');
    if (piVar5 == (int *)0x0) {
      piVar5 = (int *)0x0;
    }
    else {
      FUN_800175b0((int)piVar5,2);
      FUN_8001759c((int)piVar5,100,0xff,100,0);
      FUN_800175a0((int)piVar5,1);
      FUN_800175d0((double)FLOAT_803e4730,(double)FLOAT_803e4734,(int)piVar5);
      FUN_800175d8((int)piVar5,1);
    }
    *piVar7 = (int)piVar5;
    if (*(byte *)(piVar7 + 0x1c) >> 6 != 1) {
      DAT_803de758 = 1;
    }
  }
  fVar12 = *(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80);
  dVar11 = (double)fVar12;
  fVar13 = *(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84);
  fVar14 = *(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88);
  dVar8 = FUN_80293900((double)(fVar14 * fVar14 + (float)(dVar11 * dVar11) + fVar13 * fVar13));
  dVar10 = (double)fVar12;
  dVar9 = (double)FLOAT_803e4738;
  dVar8 = (double)(float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,
                                                                   (int)(dVar8 / (double)
                                                  FLOAT_803e4760) + 1U ^ 0x80000000) -
                                                 DOUBLE_803e4748));
  if (*(byte *)(piVar7 + 0x1c) >> 6 == 1) {
    FUN_800068c4(param_1,0x43b);
    dVar8 = (double)(float)((double)CONCAT44(0x43300000,piVar7[0x18] ^ 0x80000000) - DOUBLE_803e4748
                           );
    if ((double)FLOAT_803dca40 < dVar8) {
      if ((*(char *)((int)piVar7 + 0x6a) == '\x01') || (*(char *)((int)piVar7 + 0x6a) == '\x04')) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x19f,0,1,0xffffffff,0);
        dVar8 = (double)(**(code **)(*DAT_803dd708 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
      }
      else {
        dVar8 = (double)(**(code **)(*DAT_803dd708 + 8))(param_1,0x1bd,0,1,0xffffffff,0);
      }
    }
    uVar6 = (uint)DAT_803dc070;
    iVar4 = piVar7[0x18];
    piVar7[0x18] = iVar4 - uVar6;
    if ((int)(iVar4 - uVar6) < 0) {
      FUN_80017680(0x698);
      FUN_80017ac8(dVar8,dVar9,dVar10,dVar11,in_f5,in_f6,in_f7,in_f8,param_1);
    }
    else {
      uVar2 = *(undefined4 *)(iVar3 + 0x20);
      fVar12 = FLOAT_803e4740 + *(float *)(iVar3 + 0x1c);
      iVar4 = *(int *)(param_1 + 0xb8);
      *(undefined4 *)(iVar4 + 0x54) = *(undefined4 *)(iVar3 + 0x18);
      *(float *)(iVar4 + 0x58) = fVar12;
      *(undefined4 *)(iVar4 + 0x5c) = uVar2;
      if ((*piVar7 != 0) && (piVar7[0x18] < 0xb4)) {
        dVar8 = (double)FUN_80293f90();
        local_38 = (double)CONCAT44(0x43300000,piVar7[0x18] ^ 0x80000000);
        dVar8 = (double)(float)((double)(float)(local_38 - DOUBLE_803e4748) * dVar8);
        FUN_800068c4(0,0x460);
        FUN_800175d0(dVar8,(double)(float)((double)FLOAT_803e476c + dVar8),*piVar7);
      }
    }
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))
              (param_1,0x19f,0,1,0xffffffff,0,*DAT_803dd708,in_r10,(float)(dVar10 * dVar8),
               (float)((double)fVar13 * dVar8),(float)((double)fVar14 * dVar8));
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void LanternFireFly_hitDetect(void) {}
void LanternFireFly_release(void) {}
void LanternFireFly_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int FireFlyLantern_getExtraSize(void) { return 0x24; }
int FireFlyLantern_func08_ret_8(void) { return 0x8; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3AA0;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3AA0); }
#pragma peephole reset

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3AF0;
#pragma scheduling off
#pragma peephole off
void FireFlyLantern_render(void) { objRenderFn_8003b8f4(lbl_803E3AF0); }
#pragma peephole reset
#pragma scheduling reset
