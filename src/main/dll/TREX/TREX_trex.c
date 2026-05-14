#include "ghidra_import.h"
#include "main/dll/TREX/TREX_trex.h"

extern undefined4 FUN_800066e0();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int FUN_8003964c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005335c();
extern undefined4 FUN_8005336c();
extern undefined4 FUN_8008110c();
extern undefined4 FUN_80081114();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined8 FUN_80294d28();
extern undefined4 FUN_80294d60();

extern undefined4 DAT_80328c18;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dcd00;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e6558;
extern f64 DOUBLE_803e65a0;
extern f64 DOUBLE_803e65d8;
extern f64 DOUBLE_803e6600;
extern f64 DOUBLE_803e6628;
extern f64 DOUBLE_803e6638;
extern f64 DOUBLE_803e6650;
extern f32 lbl_803DC074;
extern f32 lbl_803DE8D0;
extern f32 lbl_803E654C;
extern f32 lbl_803E6550;
extern f32 lbl_803E6554;
extern f32 lbl_803E6560;
extern f32 lbl_803E6564;
extern f32 lbl_803E6568;
extern f32 lbl_803E6574;
extern f32 lbl_803E6578;
extern f32 lbl_803E6584;
extern f32 lbl_803E6588;
extern f32 lbl_803E658C;
extern f32 lbl_803E6590;
extern f32 lbl_803E6594;
extern f32 lbl_803E6598;
extern f32 lbl_803E659C;
extern f32 lbl_803E65A8;
extern f32 lbl_803E65AC;
extern f32 lbl_803E65B0;
extern f32 lbl_803E65B4;
extern f32 lbl_803E65C0;
extern f32 lbl_803E65C4;
extern f32 lbl_803E65C8;
extern f32 lbl_803E65CC;
extern f32 lbl_803E65D0;
extern f32 lbl_803E65D4;
extern f32 lbl_803E65E0;
extern f32 lbl_803E65E4;
extern f32 lbl_803E65E8;
extern f32 lbl_803E65F0;
extern f32 lbl_803E65F4;
extern f32 lbl_803E65F8;
extern f32 lbl_803E6608;
extern f32 lbl_803E660C;
extern f32 lbl_803E6614;
extern f32 lbl_803E6618;
extern f32 lbl_803E661C;
extern f32 lbl_803E6620;
extern f32 lbl_803E6624;
extern f32 lbl_803E6630;
extern f32 lbl_803E6634;
extern f32 lbl_803E6644;
extern f32 lbl_803E6648;
extern undefined4 uRam803de8d4;

/*
 * --INFO--
 *
 * Function: FUN_801e42f8
 * EN v1.0 Address: 0x801E42F8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801E4330
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e42f8(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  uVar1 = *(uint *)(iVar2 + 0x20);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *(undefined4 *)(iVar2 + 0x20) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4350
 * EN v1.0 Address: 0x801E4350
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E4384
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4350(int param_1)
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
 * Function: FUN_801e4378
 * EN v1.0 Address: 0x801E4378
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801E43B4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4378(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  short sVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  dVar5 = (double)*(float *)(iVar3 + 0x1c);
  dVar4 = (double)lbl_803E654C;
  if (dVar5 <= dVar4) {
    iVar2 = *(int *)(*(int *)(param_9 + 0x54) + 0x50);
    if ((((iVar2 != 0) && (sVar1 = *(short *)(iVar2 + 0x46), sVar1 != 0x119)) && (sVar1 != 0x113))
       && (dVar4 == dVar5)) {
      FUN_80006824(param_9,0x31d);
      *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
      *(float *)(iVar3 + 0x1c) = lbl_803E6550;
      *(undefined *)(param_9 + 0x36) = 0x19;
      iVar3 = 0x32;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0xa7,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      iVar3 = 10;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0xab,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  else {
    *(float *)(iVar3 + 0x1c) = (float)(dVar5 - (double)lbl_803DC074);
    if ((double)*(float *)(iVar3 + 0x1c) <= dVar4) {
      FUN_80017ac8(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e451c
 * EN v1.0 Address: 0x801E451C
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801E44EC
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e451c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  float fVar1;
  double dVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  if ((*(byte *)((int)pfVar3 + 0x1a) & 2) == 0) {
    FUN_8008110c((double)lbl_803E6554,param_9,4,0x185,5,0);
    FUN_8008110c((double)lbl_803E6554,param_9,4,0x185,5,0);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    *(byte *)((int)pfVar3 + 0x1a) = *(byte *)((int)pfVar3 + 0x1a) & 0xfd;
  }
  (**(code **)(*DAT_803dd708 + 8))(param_9,0xa9,0,1,0xffffffff,0);
  *(short *)(param_9 + 2) = *(short *)(param_9 + 2) + 4000;
  if ((*(byte *)((int)pfVar3 + 0x1a) & 1) == 0) {
    *pfVar3 = *(float *)(param_9 + 0x24);
    pfVar3[1] = *(float *)(param_9 + 0x28);
    pfVar3[2] = *(float *)(param_9 + 0x2c);
    *(byte *)((int)pfVar3 + 0x1a) = *(byte *)((int)pfVar3 + 0x1a) | 1;
    pfVar3[3] = *(float *)(param_9 + 0xc);
    pfVar3[4] = *(float *)(param_9 + 0x10);
    pfVar3[5] = *(float *)(param_9 + 0x14);
  }
  dVar2 = DOUBLE_803e6558;
  pfVar3[3] = (float)(DOUBLE_803e6558 * (double)(*pfVar3 * lbl_803DC074) + (double)pfVar3[3]);
  pfVar3[4] = (float)(dVar2 * (double)(pfVar3[1] * lbl_803DC074) + (double)pfVar3[4]);
  fVar1 = pfVar3[2] * lbl_803DC074;
  pfVar3[5] = (float)(dVar2 * (double)fVar1 + (double)pfVar3[5]);
  *(float *)(param_9 + 0xc) = pfVar3[3];
  *(float *)(param_9 + 0x10) = pfVar3[4];
  *(float *)(param_9 + 0x14) = pfVar3[5];
  *(uint *)(param_9 + 0xf4) = *(int *)(param_9 + 0xf4) - (uint)DAT_803dc070;
  if (*(int *)(param_9 + 0xf4) < 0) {
    FUN_80017ac8((double)fVar1,dVar2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  if (*(short *)(pfVar3 + 6) < 0x10) {
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
  }
  else {
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) | 1;
  }
  *(ushort *)(pfVar3 + 6) = *(short *)(pfVar3 + 6) + (ushort)DAT_803dc070;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e481c
 * EN v1.0 Address: 0x801E481C
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x801E4790
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e481c(uint param_1)
{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar2 + 0x20) == 0) {
    piVar1 = FUN_80017624(param_1,'\x01');
    *(int **)(iVar2 + 0x20) = piVar1;
    if (*(int *)(iVar2 + 0x20) != 0) {
      FUN_800175b0(*(int *)(iVar2 + 0x20),2);
      FUN_8001759c(*(int *)(iVar2 + 0x20),200,0x3c,0,0);
      FUN_800175a0(*(int *)(iVar2 + 0x20),1);
      FUN_800175d0((double)lbl_803E6560,(double)lbl_803E6564,*(int *)(iVar2 + 0x20));
    }
  }
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * lbl_803E6568;
  *(byte *)(iVar2 + 0x1a) = *(byte *)(iVar2 + 0x1a) | 2;
  FUN_80006824(param_1,0x35);
  FUN_80006824(param_1,0x2ca);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e48f4
 * EN v1.0 Address: 0x801E48F4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801E4888
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e48f4(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4928
 * EN v1.0 Address: 0x801E4928
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E48B8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4928(int param_1)
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
 * Function: FUN_801e4950
 * EN v1.0 Address: 0x801E4950
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801E48E8
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4950(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (*(int *)(iVar1 + 0x50) != 0) {
    *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) & 0xfffe;
    iVar1 = 0x32;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xa7,0,1,0xffffffff,0);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    iVar1 = 10;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0xab,0,1,0xffffffff,0);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4a14
 * EN v1.0 Address: 0x801E4A14
 * EN v1.0 Size: 580b
 * EN v1.1 Address: 0x801E49B0
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4a14(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  int *piVar1;
  undefined auStack_28 [8];
  float local_20;
  
  piVar1 = *(int **)(param_9 + 0x5c);
  if (*piVar1 == 0) {
    *piVar1 = *(int *)(param_9 + 0x7c);
  }
  if (*piVar1 != 0) {
    *param_9 = 0;
    param_9[2] = param_9[2] + (ushort)DAT_803dc070 * -800;
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (*(int *)(param_9 + 0x7a) < 0) {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    else {
      if (*(char *)(piVar1 + 5) == '\0') {
        piVar1[2] = *(int *)(param_9 + 0x12);
        piVar1[3] = *(int *)(param_9 + 0x14);
        piVar1[4] = *(int *)(param_9 + 0x16);
        *(undefined *)(piVar1 + 5) = 1;
      }
      *(float *)(param_9 + 6) = (float)piVar1[2] * lbl_803DC074 + *(float *)(param_9 + 6);
      *(float *)(param_9 + 8) = (float)piVar1[3] * lbl_803DC074 + *(float *)(param_9 + 8);
      *(float *)(param_9 + 10) = (float)piVar1[4] * lbl_803DC074 + *(float *)(param_9 + 10);
      local_20 = lbl_803E6574;
      FUN_8008110c((double)lbl_803E6578,param_9,4,0x185,5,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0xa9,auStack_28,1,0xffffffff,0);
      if (*(short *)(piVar1 + 1) < 0x10) {
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      }
      else {
        *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 5;
        *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
        *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x48) = 0x10;
        *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x4c) = 0x10;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
      }
      *(ushort *)(piVar1 + 1) = *(short *)(piVar1 + 1) + (ushort)DAT_803dc070;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4c58
 * EN v1.0 Address: 0x801E4C58
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801E4BAC
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4c58(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  uVar1 = *(uint *)(iVar2 + 0x18);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *(undefined4 *)(iVar2 + 0x18) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4cb0
 * EN v1.0 Address: 0x801E4CB0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E4C00
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4cb0(int param_1)
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
 * Function: FUN_801e4cd8
 * EN v1.0 Address: 0x801E4CD8
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801E4C30
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4cd8(uint param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(*(int *)(param_1 + 0x54) + 0x50);
  if ((iVar1 != 0) && (*(float *)(iVar2 + 0x20) == lbl_803E6584)) {
    if (*(short *)(iVar1 + 0x46) == 0x8e) {
      FUN_80006824(param_1,0x36);
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(float *)(iVar2 + 0x20) = lbl_803E6588;
    *(undefined *)(param_1 + 0x36) = 0;
    FUN_80081114(param_1,2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e4d6c
 * EN v1.0 Address: 0x801E4D6C
 * EN v1.0 Size: 824b
 * EN v1.1 Address: 0x801E4CCC
 * EN v1.1 Size: 812b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e4d6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  float fVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  double dVar5;
  float local_28;
  float local_24;
  float local_20;
  undefined4 local_18;
  uint uStack_14;
  
  pfVar3 = *(float **)(param_9 + 0x5c);
  iVar2 = FUN_80017a98();
  fVar1 = lbl_803E6584;
  dVar5 = (double)pfVar3[8];
  dVar4 = (double)lbl_803E6584;
  if (dVar5 == dVar4) {
    *(undefined4 *)(param_9 + 0x40) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0x42) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x44) = *(undefined4 *)(param_9 + 10);
    uStack_14 = FUN_80017760(0xffffff9c,100);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_9 + 4) =
         lbl_803E6590 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e65a0) +
         lbl_803E658C;
    if (*(char *)(pfVar3 + 7) == '\0') {
      *pfVar3 = *(float *)(param_9 + 0x12);
      pfVar3[1] = *(float *)(param_9 + 0x14);
      pfVar3[2] = *(float *)(param_9 + 0x16);
      *(undefined *)(pfVar3 + 7) = 1;
      pfVar3[3] = *(float *)(param_9 + 6);
      pfVar3[4] = *(float *)(param_9 + 8);
      pfVar3[5] = *(float *)(param_9 + 10);
    }
    fVar1 = lbl_803E6594;
    pfVar3[3] = lbl_803E6594 * *pfVar3 * lbl_803DC074 + pfVar3[3];
    pfVar3[4] = fVar1 * pfVar3[1] * lbl_803DC074 + pfVar3[4];
    pfVar3[5] = fVar1 * pfVar3[2] * lbl_803DC074 + pfVar3[5];
    *(float *)(param_9 + 6) = pfVar3[3];
    *(float *)(param_9 + 8) = pfVar3[4];
    *(float *)(param_9 + 10) = pfVar3[5];
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (((*(int *)(param_9 + 0x7a) < 0) ||
        ((iVar2 != 0 && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)))) &&
       (pfVar3[8] == lbl_803E6584)) {
      *(undefined *)(param_9 + 0x1b) = 0;
      pfVar3[8] = lbl_803E6588;
    }
    iVar2 = FUN_80017730();
    *param_9 = (short)iVar2;
    *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
    if ((*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') && (pfVar3[8] == lbl_803E6584)) {
      FUN_80081114(param_9,2);
      pfVar3[8] = lbl_803E6588;
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    local_28 = lbl_803E6598 * -*pfVar3;
    local_24 = lbl_803E6598 * -pfVar3[1];
    local_20 = lbl_803E6598 * -pfVar3[2];
    FUN_8008110c((double)lbl_803E659C,param_9,2,0x156,0xf,&local_28);
    FUN_8008110c((double)lbl_803E659C,param_9,2,0x156,0xf,&local_28);
    FUN_8008110c((double)lbl_803E659C,param_9,2,0x156,0xf,&local_28);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xa8,0,2,0xffffffff,0);
  }
  else {
    pfVar3[8] = (float)(dVar5 - (double)lbl_803DC074);
    if ((double)pfVar3[8] <= dVar4) {
      pfVar3[8] = fVar1;
      FUN_80017ac8(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e50a4
 * EN v1.0 Address: 0x801E50A4
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x801E4FF8
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e50a4(int param_1)
{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) = *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) | 1;
  if (*(int *)(iVar2 + 0x18) == 0) {
    piVar1 = FUN_80017624(param_1,'\x01');
    *(int **)(iVar2 + 0x18) = piVar1;
    if (*(int *)(iVar2 + 0x18) != 0) {
      FUN_800175b0(*(int *)(iVar2 + 0x18),2);
      FUN_8001759c(*(int *)(iVar2 + 0x18),0,0x5a,0x96,0);
      FUN_800175a0(*(int *)(iVar2 + 0x18),1);
      FUN_800175d0((double)lbl_803E65A8,(double)lbl_803E65AC,*(int *)(iVar2 + 0x18));
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e514c
 * EN v1.0 Address: 0x801E514C
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x801E50B0
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e514c(uint param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    cVar1 = *(char *)(param_3 + iVar3 + 0x81);
    if (cVar1 == '\x01') {
      *(undefined *)(iVar2 + 4) = 1;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar2 + 4) = 2;
    }
  }
  *(undefined2 *)(param_3 + 0x6e) = 0xfffc;
  if (*(short *)(param_1 + 0xb4) != -1) {
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffb;
    iVar2 = FUN_8002fc3c((double)lbl_803E65B0,(double)lbl_803DC074);
    if (iVar2 != 0) {
      FUN_80006824(param_1,0x315);
    }
  }
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e521c
 * EN v1.0 Address: 0x801E521C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801E5194
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e521c(int param_1)
{
  if (**(int **)(param_1 + 0xb8) != 0) {
    ObjLink_DetachChild(param_1,**(int **)(param_1 + 0xb8));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e524c
 * EN v1.0 Address: 0x801E524C
 * EN v1.0 Size: 884b
 * EN v1.1 Address: 0x801E51CC
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e524c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int local_18;
  int local_14 [2];
  
  piVar4 = *(int **)(param_9 + 0xb8);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
  if (*piVar4 == 0) {
    iVar1 = FUN_80017b00(&local_18,local_14);
    for (local_18 = 0; local_18 < local_14[0]; local_18 = local_18 + 1) {
      iVar3 = *(int *)(iVar1 + local_18 * 4);
      if (*(short *)(iVar3 + 0x46) == 0x121) {
        *piVar4 = iVar3;
        ObjLink_AttachChild(param_9,*piVar4,1);
        local_18 = local_14[0];
      }
    }
  }
  if (((*(byte *)(param_9 + 0xaf) & 4) == 0) || (uVar2 = FUN_80017690(0x92a), uVar2 != 0)) {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_80006ba8(0,0x100);
      (**(code **)(*DAT_803dd6d4 + 0x84))(param_9,0);
      if (*(char *)((int)piVar4 + 5) == '\0') {
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))(1,param_9,0xffffffff);
        *(undefined *)((int)piVar4 + 5) = 1;
      }
      else {
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))(2,param_9,0xffffffff);
      }
    }
    if (*(int *)(param_9 + 0x30) != 0) {
      iVar3 = *(int *)(*(int *)(param_9 + 0x30) + 0xf4);
      iVar1 = FUN_8003964c(param_9,0);
      if (((iVar1 == 0) || (8 < iVar3)) || (*(short *)(param_9 + 0xa0) == 5)) {
        if (((iVar1 != 0) && (8 < iVar3)) && (*(short *)(param_9 + 0xa0) != 9)) {
          *(undefined2 *)(iVar1 + 4) = 0;
          FUN_800305f8((double)lbl_803E65B4,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,9,0,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else {
        *(undefined2 *)(iVar1 + 4) = *(undefined2 *)(*(int *)(param_9 + 0x30) + 4);
        FUN_800305f8((double)lbl_803E65B4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,5,0,param_12,param_13,param_14,param_15,param_16);
      }
    }
    iVar1 = FUN_8002fc3c((double)lbl_803E65B0,(double)lbl_803DC074);
    if (iVar1 != 0) {
      FUN_80006824(param_9,0x315);
    }
  }
  else {
    FUN_80006ba8(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x84))(param_9,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
    FUN_80017698(0x92a,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e55c0
 * EN v1.0 Address: 0x801E55C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E5450
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e55c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e55c4
 * EN v1.0 Address: 0x801E55C4
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801E5564
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e55c4(uint param_1)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  if (0 < *(int *)(param_1 + 0xf4)) {
    *(int *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) + -1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *psVar3 = *psVar3 - (ushort)DAT_803dc070;
  iVar1 = FUN_80017a98();
  FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
  if (*psVar3 < 1) {
    FUN_80017760(0,10);
    uVar2 = FUN_80017690(0xa71);
    if (uVar2 == 0) {
      FUN_80006824(param_1,0x316);
    }
    uVar2 = FUN_80017760(400,600);
    *psVar3 = (short)uVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5684
 * EN v1.0 Address: 0x801E5684
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E5688
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5684(int param_1)
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
 * Function: FUN_801e56ac
 * EN v1.0 Address: 0x801E56AC
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801E56BC
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e56ac(int param_1)
{
  uint uVar1;
  
  if (((*(short *)(param_1 + 0x46) == 0x173) && (*(int *)(param_1 + 0xf4) == 0)) &&
     (uVar1 = FUN_80017690(0xa4b), uVar1 != 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5734
 * EN v1.0 Address: 0x801E5734
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801E579C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5734(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5790
 * EN v1.0 Address: 0x801E5790
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801E57F0
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5790(void)
{
  int iVar1;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    FUN_8005336c(8);
    FUN_8003b818(iVar1);
    FUN_8005335c(8);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e57e0
 * EN v1.0 Address: 0x801E57E0
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801E586C
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e57e0(short *param_1)
{
  int iVar1;
  double dVar2;
  undefined8 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * lbl_803DC074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * lbl_803DC074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * lbl_803DC074 + *(float *)(param_1 + 10);
  local_2c = lbl_803E65C4;
  local_28 = lbl_803E65C4;
  local_24 = lbl_803E65C4;
  local_30 = lbl_803E65C0;
  if ((int)*(uint *)(param_1 + 0x7a) < 0x3d) {
    uStack_1c = *(uint *)(param_1 + 0x7a) ^ 0x80000000;
    local_20 = 0x43300000;
    local_30 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e65d8) / lbl_803E65C8;
    local_18 = 0x43300000;
    iVar1 = (int)(lbl_803E65CC *
                 ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e65d8) / lbl_803E65C8
                 ));
    local_10 = (longlong)iVar1;
    *(char *)(param_1 + 0x1b) = (char)iVar1;
    uStack_14 = uStack_1c;
  }
  local_34 = 0;
  local_36 = 0;
  local_38 = 0;
  (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  dVar4 = (double)(*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42));
  dVar5 = (double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
  dVar2 = (double)lbl_803E65D0;
  local_2c = (float)((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)) / dVar2);
  local_28 = (float)(dVar4 / dVar2);
  local_24 = (float)(dVar5 / dVar2);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  local_2c = local_2c * lbl_803E65D4;
  local_28 = local_28 * lbl_803E65D4;
  local_24 = local_24 * lbl_803E65D4;
  uVar3 = (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  *param_1 = *param_1 + (ushort)DAT_803dc070 * 0x374;
  param_1[1] = param_1[1] + (ushort)DAT_803dc070 * 300;
  *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
  if (*(int *)(param_1 + 0x7a) < 0) {
    FUN_80017ac8(uVar3,dVar4,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e59ec
 * EN v1.0 Address: 0x801E59EC
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801E5A9C
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e59ec(uint param_1)
{
  float fVar1;
  uint uVar2;
  int *piVar3;
  
  *(undefined4 *)(param_1 + 0xf4) = 0xb4;
  uVar2 = FUN_80017760(0x14,0x28);
  fVar1 = lbl_803E65E0;
  *(float *)(param_1 + 0x24) =
       -(lbl_803E65E4 * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e65d8)
        + lbl_803E65E0);
  *(float *)(param_1 + 0x28) = lbl_803E65C4;
  *(float *)(param_1 + 0x2c) = lbl_803E65E8;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * fVar1;
  piVar3 = (int *)FUN_80006b14(0x75);
  (**(code **)(*piVar3 + 4))(param_1,DAT_803dcd00,0,0x10002,0xffffffff,0);
  DAT_803dcd00 = DAT_803dcd00 + 1;
  if (3 < DAT_803dcd00) {
    DAT_803dcd00 = 1;
  }
  FUN_80006b0c((undefined *)piVar3);
  FUN_80006824(param_1,0x35);
  FUN_80006824(param_1,0x2ca);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5afc
 * EN v1.0 Address: 0x801E5AFC
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E5BB8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5afc(int param_1)
{
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dd6f4 + 8))(param_1,0xffff,0,0,0);
  if (*(uint *)(param_1 + 0xf8) != 0) {
    FUN_80017620(*(uint *)(param_1 + 0xf8));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5b80
 * EN v1.0 Address: 0x801E5B80
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801E5C34
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5b80(int param_1)
{
  FUN_8003b818(param_1);
  if (*(short *)(param_1 + 0x46) == 0x171) {
    FUN_8008110c((double)lbl_803E65F8,param_1,4,0x185,5,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5bd4
 * EN v1.0 Address: 0x801E5BD4
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x801E5C90
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5bd4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  int local_28;
  int local_24 [6];
  
  if ((*(int *)(param_9 + 0x4c) != 0) && (*(short *)(*(int *)(param_9 + 0x4c) + 0x18) != -1)) {
    local_24[2] = (int)DAT_803dc071;
    local_24[1] = 0x43300000;
    local_24[0] = (**(code **)(*DAT_803dd6d4 + 0x14))
                            ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) -
                                            DOUBLE_803e6600));
    if ((local_24[0] != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar4 = (int)*(char *)(*(int *)(param_9 + 0xb8) + 0x57);
      iVar5 = 0;
      uVar6 = extraout_f1;
      piVar1 = (int *)FUN_80017b00(local_24,&local_28);
      iVar3 = 0;
      for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar2 = *piVar1;
        if (*(short *)(iVar2 + 0xb4) == iVar4) {
          iVar5 = iVar2;
        }
        if (((*(short *)(iVar2 + 0xb4) == -2) && (*(short *)(iVar2 + 0x44) == 0x10)) &&
           (iVar4 == *(char *)(*(int *)(iVar2 + 0xb8) + 0x57))) {
          iVar3 = iVar3 + 1;
        }
        piVar1 = piVar1 + 1;
      }
      if (((iVar3 < 2) && (iVar5 != 0)) && (*(short *)(iVar5 + 0xb4) != -1)) {
        *(undefined2 *)(iVar5 + 0xb4) = 0xffff;
        uVar6 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar4);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
      FUN_80017ac8(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5dd0
 * EN v1.0 Address: 0x801E5DD0
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x801E5E04
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5dd0(int param_1,int param_2)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar3 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar3 + 0x6e) = 0xffff;
  *(float *)(iVar3 + 0x24) =
       lbl_803E65F4 /
       (lbl_803E65F4 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e6600));
  *(undefined4 *)(iVar3 + 0x28) = 0xffffffff;
  iVar2 = *(int *)(param_1 + 0xf4);
  if ((iVar2 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar3);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar2 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar2 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar3);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar3,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(short *)(param_1 + 0x46) == 0x171) {
    piVar1 = FUN_80017624(param_1,'\x01');
    if (piVar1 != (int *)0x0) {
      FUN_800175b0((int)piVar1,2);
      FUN_8001759c((int)piVar1,200,0x3c,0,0);
      FUN_800175d0((double)lbl_803E6608,(double)lbl_803E660C,(int)piVar1);
    }
    *(int **)(param_1 + 0xf8) = piVar1;
  }
  lbl_803DE8D0 = lbl_803E65F0;
  uRam803de8d4 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5f78
 * EN v1.0 Address: 0x801E5F78
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801E5FA4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5f78(int param_1)
{
  FUN_8000680c(param_1,0x40);
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e5fc4
 * EN v1.0 Address: 0x801E5FC4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E5FEC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e5fc4(int param_1)
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
 * Function: FUN_801e5fec
 * EN v1.0 Address: 0x801E5FEC
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801E601C
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e5fec(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  undefined auStack_28 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  uVar1 = FUN_80017760(0,1);
  if (uVar1 == 0) {
    *(undefined *)(param_3 + 0x90) = 8;
  }
  else {
    *(undefined *)(param_3 + 0x90) = 4;
  }
  *(undefined *)(param_3 + 0x56) = 0;
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffdf;
  iVar2 = FUN_80017a98();
  if ((iVar2 != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    local_20 = lbl_803E6614;
    local_22 = 0xc0d;
    local_1c = local_1c - *(float *)(param_1 + 0x18);
    local_18 = local_18 - *(float *)(param_1 + 0x1c);
    local_14 = local_14 - *(float *)(param_1 + 0x20);
    for (iVar2 = 0; iVar2 < (int)(uint)DAT_803dc070; iVar2 = iVar2 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a8,auStack_28,6,0xffffffff,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e60cc
 * EN v1.0 Address: 0x801E60CC
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x801E6144
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e60cc(uint param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  bool bVar5;
  double dVar6;
  undefined auStack_38 [6];
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24 [2];
  uint uStack_1c;
  
  iVar4 = FUN_80017a98();
  dVar6 = (double)FUN_8001771c((float *)(iVar4 + 0x18),(float *)(param_1 + 0x18));
  bVar5 = FUN_800067f0(param_1,0x40);
  if (bVar5) {
    if ((double)lbl_803E6618 <= dVar6) {
      FUN_8000680c(param_1,0x40);
    }
  }
  else if (dVar6 < (double)lbl_803E6618) {
    FUN_80006824(param_1,0x72);
  }
  if (*(short *)(param_1 + 0x46) != 0x3e4) {
    if (*(int *)(param_1 + 0xf8) == 0) {
      *(undefined4 *)(param_1 + 0xf8) = 1;
      uStack_1c = FUN_80017760(0,0x5a);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_24[1] = 176.0;
      FUN_800305c4((double)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6628) /
                           lbl_803E6618),param_1);
    }
    FUN_8002fc3c((double)lbl_803E661C,(double)lbl_803DC074);
  }
  if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
    local_30 = lbl_803E6614;
    local_32 = 0xc0d;
    local_2c = lbl_803E6620;
    local_28 = lbl_803E6624;
    local_24[0] = lbl_803E6620;
    ObjPath_GetPointWorldPosition(param_1,0,&local_2c,&local_28,local_24,1);
    if (*(int *)(param_1 + 0x30) == 0) {
      fVar1 = *(float *)(param_1 + 0xc);
      fVar2 = *(float *)(param_1 + 0x10);
      fVar3 = *(float *)(param_1 + 0x14);
    }
    else {
      fVar1 = *(float *)(param_1 + 0x18);
      fVar2 = *(float *)(param_1 + 0x1c);
      fVar3 = *(float *)(param_1 + 0x20);
    }
    local_24[0] = local_24[0] - fVar3;
    local_28 = local_28 - fVar2;
    local_2c = local_2c - fVar1;
    for (iVar4 = 0; iVar4 < (int)(uint)DAT_803dc070; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7c7,auStack_38,2,0xffffffff,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e62b8
 * EN v1.0 Address: 0x801E62B8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E63C8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e62b8(int param_1)
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
 * Function: FUN_801e62e0
 * EN v1.0 Address: 0x801E62E0
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801E63FC
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e62e0(int param_1)
{
  double dVar1;
  undefined8 local_18;
  
  if (*(short *)(param_1 + 0x46) == 0x187) {
    FUN_8002fc3c((double)lbl_803E6644,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e6650))
    ;
  }
  else if (*(short *)(param_1 + 0x46) == 0x803) {
    FUN_80017a98();
    dVar1 = DOUBLE_803e6638;
    if ((*(ushort *)(*(int *)(param_1 + 0x30) + 0xb0) & 0x1000) == 0) {
      *(float *)(param_1 + 0x24) =
           (float)((double)CONCAT44(0x43300000,
                                    (int)*(short *)(*(int *)(param_1 + 0x30) + 4) ^ 0x80000000) -
                  DOUBLE_803e6638) * lbl_803E6634;
      *(short *)(param_1 + 4) =
           (short)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_1 + 4) ^ 0x80000000) - dVar1)
                       + *(float *)(param_1 + 0x24));
    }
    else {
      *(float *)(param_1 + 0x24) = lbl_803E6630;
    }
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
    FUN_8002fc3c((double)lbl_803E6648,(double)(float)(local_18 - DOUBLE_803e6650));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e63f4
 * EN v1.0 Address: 0x801E63F4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x801E6510
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e63f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  if (param_9[0x23] != 0x803) {
    *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
    FUN_800305f8((double)lbl_803E6630,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e64c4
 * EN v1.0 Address: 0x801E64C4
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801E6578
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e64c4(void)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_80286840();
  uVar2 = FUN_80017690((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1e));
  if (uVar2 != 0) {
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6510
 * EN v1.0 Address: 0x801E6510
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801E65EC
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6510(uint param_1)
{
  uint uVar1;
  
  uVar1 = FUN_80017690((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (uVar1 != 0) {
    FUN_80006824(param_1,0x34);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6558
 * EN v1.0 Address: 0x801E6558
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x801E66B0
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6558(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  iVar1 = FUN_80017a98();
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar2 = (**(code **)(*DAT_803dd72c + 0x8c))();
  uVar4 = FUN_80294d28(iVar1,-param_10);
  switch(*(undefined *)(iVar3 + 1)) {
  case 0:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,2);
    break;
  case 1:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,8);
    break;
  case 2:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,4);
    break;
  case 3:
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x1c);
    break;
  case 4:
    FUN_80017688(0x66c);
    break;
  case 5:
    FUN_80017688(0x86a);
    break;
  case 6:
    FUN_80017688(0xc1);
    break;
  case 7:
    FUN_80017688(0x13d);
    FUN_80017688(0x5d6);
    break;
  case 8:
    FUN_80017688(0x3f5);
    break;
  case 0x17:
    *(undefined *)(iVar2 + 10) = 10;
  }
  if ((int)*(short *)(&DAT_80328c18 + *(char *)(iVar3 + 1) * 0xc) != 0xffffffff) {
    FUN_80017698((int)*(short *)(&DAT_80328c18 + *(char *)(iVar3 + 1) * 0xc),1);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void SB_FireBall_release(void) {}
void SB_FireBall_initialise(void) {}
void SB_CloudBall_release(void) {}
void SB_CloudBall_initialise(void) {}
void SB_KyteCage_render(void) {}
void SB_KyteCage_hitDetect(void) {}
void SB_KyteCage_release(void) {}
void SB_KyteCage_initialise(void) {}
void SB_CageKyte_free(void) {}
void SB_CageKyte_hitDetect(void) {}
void SB_CageKyte_release(void) {}
void SB_CageKyte_initialise(void) {}
void SB_SeqDoor_free(void) {}
void SB_SeqDoor_hitDetect(void) {}
void SB_SeqDoor_release(void) {}
void SB_SeqDoor_initialise(void) {}
void SB_MiniFire_hitDetect(void) {}
void SB_MiniFire_release(void) {}
void SB_MiniFire_initialise(void) {}
void ShipBattle_hitDetect(void) {}
void ShipBattle_release(void) {}
void ShipBattle_initialise(void) {}
void Flag_free(void) {}
void Flag_hitDetect(void) {}
void Flag_release(void) {}
void Flag_initialise(void) {}
void SB_ShipGunBroke_free(void) {}
void SB_ShipGunBroke_hitDetect(void) {}
void SB_ShipGunBroke_init(void) {}
void SB_ShipGunBroke_release(void) {}
void SB_ShipGunBroke_initialise(void) {}
void shop_hitDetect(void) {}
void shop_release(void) {}
void shop_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int SB_CloudBall_getExtraSize(void) { return 0x24; }
int SB_CloudBall_func08(void) { return 0x0; }
int SB_KyteCage_getExtraSize(void) { return 0x8; }
int SB_KyteCage_func08(void) { return 0x0; }
int SB_CageKyte_getExtraSize(void) { return 0x2; }
int SB_CageKyte_func08(void) { return 0x1; }
int SB_SeqDoor_getExtraSize(void) { return 0x0; }
int SB_SeqDoor_func08(void) { return 0x0; }
int SB_MiniFire_getExtraSize(void) { return 0x2; }
int SB_MiniFire_func08(void) { return 0x0; }
int ShipBattle_getExtraSize(void) { return 0x140; }
int ShipBattle_func08(void) { return 0xb; }
int Lamp_getExtraSize(void) { return 0x1; }
int Flag_getExtraSize(void) { return 0x0; }
int Flag_func08(void) { return 0x0; }
int SB_ShipGunBroke_getExtraSize(void) { return 0x1; }
int SB_ShipGunBroke_func08(void) { return 0x0; }
int shop_getExtraSize(void) { return 0x5; }
int shop_func08(void) { return 0x0; }
int fn_801E66DC(void) { return 0x0; }
int fn_801E66E4(void) { return 0x0; }

/* 16b chained patterns. */
s32 shop_getStateField1(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x1); }
s32 shop_setScale(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x0); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58E8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5920;
extern f32 lbl_803E5978;
extern f32 lbl_803E59A8;
extern f32 lbl_803E59C8;
#pragma peephole off
void SB_CloudBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E58E8); }
void SB_SeqDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5920); }
void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5978); }
void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E59A8); }
void shop_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E59C8); }
#pragma peephole reset
