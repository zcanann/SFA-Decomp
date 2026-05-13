#include "ghidra_import.h"
#include "main/dll/dll_19E.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern void* FUN_80017624();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017760();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80017b00();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053754();
extern int FUN_8005b024();

extern undefined4 DAT_803dc071;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6fc;
extern void* DAT_803de838;
extern f64 DOUBLE_803e5b38;
extern f64 DOUBLE_803e5b40;
extern f32 lbl_803DC074;
extern f32 lbl_803E5B30;
extern f32 lbl_803E5B34;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B4C;

/*
 * --INFO--
 *
 * Function: dfsh_objcreator_update
 * EN v1.0 Address: 0x801C3BB0
 * EN v1.0 Size: 740b
 * EN v1.1 Address: 0x801C3CC4
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_objcreator_update(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  byte bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  int local_28;
  int local_24 [5];
  
  iVar2 = *(int *)(param_9 + 0x4c);
  iVar7 = *(int *)(param_9 + 0xb8);
  if (((iVar2 != 0) && (*(short *)(iVar2 + 0x18) != -1)) && (*(int *)(iVar2 + 0x14) != 0x4ca62)) {
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar7 + 0x8b); iVar2 = iVar2 + 1) {
      bVar1 = *(byte *)(iVar7 + iVar2 + 0x81);
      if (bVar1 == 2) {
        *(undefined *)(iVar7 + 0x144) = 1;
      }
      else if ((bVar1 < 2) && (bVar1 != 0)) {
        *(undefined *)(iVar7 + 0x144) = 0;
      }
    }
    local_24[2] = (int)DAT_803dc071;
    local_24[1] = 0x43300000;
    local_28 = (**(code **)(*DAT_803dd6d4 + 0x14))
                         ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e5b38
                                         ),param_9);
    if ((local_28 != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar6 = (int)*(char *)(iVar7 + 0x57);
      iVar2 = 0;
      uVar8 = extraout_f1;
      piVar3 = (int *)FUN_80017b00(&local_28,local_24);
      iVar5 = 0;
      for (local_28 = 0; local_28 < local_24[0]; local_28 = local_28 + 1) {
        iVar4 = *piVar3;
        if (*(short *)(iVar4 + 0xb4) == iVar6) {
          iVar2 = iVar4;
        }
        if (((*(short *)(iVar4 + 0xb4) == -2) && (*(short *)(iVar4 + 0x44) == 0x10)) &&
           (iVar6 == *(char *)(*(int *)(iVar4 + 0xb8) + 0x57))) {
          iVar5 = iVar5 + 1;
        }
        piVar3 = piVar3 + 1;
      }
      if (((iVar5 < 2) && (iVar2 != 0)) && (*(short *)(iVar2 + 0xb4) != -1)) {
        *(undefined2 *)(iVar2 + 0xb4) = 0xffff;
        uVar8 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar6);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
      FUN_80017ac8(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    *(float *)(iVar7 + 0x148) = *(float *)(iVar7 + 0x148) - lbl_803DC074;
    if (*(float *)(iVar7 + 0x148) < lbl_803E5B34) {
      iVar2 = FUN_80017a98();
      local_24[2] = FUN_80017760(0xb4,0xf0);
      local_24[2] = local_24[2] ^ 0x80000000;
      local_24[1] = 0x43300000;
      *(float *)(iVar7 + 0x148) =
           (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e5b40);
      if ((*(char *)(param_9 + 0xac) == -1) &&
         ((iVar2 == 0 || (iVar2 = FUN_8005b024(), iVar2 == 0xb)))) {
        FUN_80006824(param_9,0x4a0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: DFSH_LaserBeam_init
 * EN v1.0 Address: 0x801C3E94
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x801C3F28
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DFSH_LaserBeam_init(int param_1,int param_2)
{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_2 + 0x14) != 0x4ca62) {
    *(undefined2 *)(iVar4 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
    *(undefined2 *)(iVar4 + 0x6e) = 0xffff;
    *(float *)(iVar4 + 0x24) =
         lbl_803E5B30 /
         (lbl_803E5B30 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e5b38));
    *(undefined4 *)(iVar4 + 0x28) = 0xffffffff;
    iVar3 = *(int *)(param_1 + 0xf4);
    if ((iVar3 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar4);
      *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
    }
    else if ((iVar3 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar3 + -1)) {
      (**(code **)(*DAT_803dd6d4 + 0x24))(iVar4);
      if (*(short *)(param_2 + 0x18) != -1) {
        (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar4,param_2);
      }
      *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
    }
    if (*(short *)(param_1 + 0x46) != 0x1d9) {
      *(undefined *)(iVar4 + 0x144) = 1;
    }
    if (*(int *)(iVar4 + 0x140) == 0) {
      iVar3 = param_1;
      if (*(char *)(iVar4 + 0x144) != '\0') {
        iVar3 = 0;
      }
      piVar1 = FUN_80017624(iVar3,'\x01');
      *(int **)(iVar4 + 0x140) = piVar1;
      if (*(int *)(iVar4 + 0x140) != 0) {
        FUN_800175b0(*(int *)(iVar4 + 0x140),2);
        FUN_8001759c(*(int *)(iVar4 + 0x140),0x96,0x32,0xff,0xff);
        FUN_800175d0((double)lbl_803E5B48,(double)lbl_803E5B4C,*(int *)(iVar4 + 0x140));
      }
    }
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined *)(param_1 + 0x37) = 0;
    uVar2 = FUN_80017760(0xb4,0xf0);
    *(float *)(iVar4 + 0x148) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5b40);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c4098
 * EN v1.0 Address: 0x801C4098
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C4130
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c4098(int param_1)
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
 * Function: FUN_801c40c0
 * EN v1.0 Address: 0x801C40C0
 * EN v1.0 Size: 752b
 * EN v1.1 Address: 0x801C4164
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c40c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  short *psVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0x26);
  psVar4 = *(short **)(param_9 + 0x5c);
  uVar1 = GameBit_Get(0x589);
  if (uVar1 == 0) {
    if ((*(int *)(param_9 + 0x7c) == 0) &&
       (uVar1 = GameBit_Get((int)*(char *)(iVar5 + 0x1f) + 0xf6), uVar1 != 0)) {
      piVar2 = (int *)FUN_80006b14(0x82);
      (**(code **)(*piVar2 + 4))(param_9,0,0,1,0xffffffff,0);
      in_r8 = 0;
      in_r9 = *piVar2;
      (**(code **)(in_r9 + 4))(param_9,1,0,1,0xffffffff);
      param_1 = FUN_80006824((uint)param_9,0xaf);
      FUN_80006b0c((undefined *)piVar2);
      psVar4[1] = 1;
      *(undefined4 *)(param_9 + 0x7c) = 1;
    }
    if (psVar4[1] != 0) {
      *psVar4 = *psVar4 - psVar4[1] * (short)(int)lbl_803DC074;
    }
    uVar1 = FUN_80017ae8();
    if (((uVar1 & 0xff) != 0) && (*psVar4 < 1)) {
      puVar3 = FUN_80017aa4(0x38,0x11);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x10);
      *(undefined4 *)(puVar3 + 10) = *(undefined4 *)(iVar5 + 0x14);
      *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
      *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
      *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
      *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
      *(undefined *)((int)puVar3 + 0x27) = 3;
      puVar3[0xc] = 0x1e7;
      puVar3[0x18] = 0xffff;
      puVar3[0xd] = 0xffff;
      puVar3[0xe] = 0xffff;
      *(char *)(puVar3 + 0x15) = (char)((ushort)*param_9 >> 8);
      *(undefined *)((int)puVar3 + 0x2b) = 2;
      uVar1 = GameBit_Get(0xfc);
      if (uVar1 == 0) {
        puVar3[0x11] = 0xffff;
      }
      else {
        puVar3[0x11] = 0x49;
      }
      *(undefined *)((int)puVar3 + 0x29) = 0xff;
      *(undefined *)(puVar3 + 0x17) = 0xff;
      puVar3[0x1a] = 0xffff;
      FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                   *(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),in_r8,in_r9,
                   in_r10);
      *psVar4 = 100;
      psVar4[1] = 0;
    }
  }
  else {
    *(undefined4 *)(param_9 + 0x7c) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c43b0
 * EN v1.0 Address: 0x801C43B0
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801C4400
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c43b0(int param_1)
{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6fc + 0x18))();
  FUN_80006b0c(DAT_803de838);
  DAT_803de838 = (void*)0x0;
  if (*piVar1 != 0) {
    FUN_80053754();
  }
  *piVar1 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: dfsh_objcreator_release
 * EN v1.0 Address: 0x801C3E34
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_objcreator_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_objcreator_initialise
 * EN v1.0 Address: 0x801C3E38
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_objcreator_initialise(void)
{
}


/* Trivial 4b 0-arg blr leaves. */
void DFSH_LaserBeam_render(void) {}
void DFSH_LaserBeam_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int DFSH_LaserBeam_getExtraSize(void) { return 0x4c; }
int DFSH_LaserBeam_func08(void) { return 0x0; }
