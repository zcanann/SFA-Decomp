#include "ghidra_import.h"
#include "main/dll/dll_15A.h"

extern undefined4 FUN_80006b0c();
extern undefined8 FUN_80017698();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8003b818();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern double FUN_80293900();

extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de748;
extern f64 DOUBLE_803e4660;
extern f32 lbl_803E4640;
extern f32 lbl_803E4644;
extern f32 lbl_803E4650;
extern f32 lbl_803E4658;
extern f32 lbl_803E466C;
extern f32 lbl_803E4670;

/*
 * --INFO--
 *
 * Function: FUN_801833e4
 * EN v1.0 Address: 0x801833E4
 * EN v1.0 Size: 2192b
 * EN v1.1 Address: 0x8018393C
 * EN v1.1 Size: 1824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801833e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  short *psVar2;
  int iVar3;
  undefined2 *puVar4;
  undefined8 uVar5;
  double dVar6;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    uVar5 = FUN_80017698((int)*(short *)(param_11 + 0xe),1);
    switch(*(char *)(param_11 + 0x11)) {
    case '\x01':
      puVar4 = FUN_80017aa4(0x24,0x3d3);
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0xd] = 400;
      psVar2 = (short *)FUN_80017ae4(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar4,5,*(undefined *)(param_9 + 0xac),0xffffffff,
                                     *(uint **)(param_9 + 0x30),param_14,param_15,param_16);
      *(float *)(psVar2 + 0x12) = *(float *)(param_9 + 0xc) - *(float *)(param_10 + 0xc);
      *(float *)(psVar2 + 0x16) = *(float *)(param_9 + 0x14) - *(float *)(param_10 + 0x14);
      dVar6 = (double)(*(float *)(psVar2 + 0x12) * *(float *)(psVar2 + 0x12) +
                      *(float *)(psVar2 + 0x16) * *(float *)(psVar2 + 0x16));
      if (dVar6 != (double)lbl_803E4650) {
        dVar6 = FUN_80293900(dVar6);
        *(float *)(psVar2 + 0x12) = (float)((double)*(float *)(psVar2 + 0x12) / dVar6);
        *(float *)(psVar2 + 0x16) = (float)((double)*(float *)(psVar2 + 0x16) / dVar6);
      }
      uStack_1c = FUN_80017760(0,0x19);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar2 + 0x12) =
           *(float *)(psVar2 + 0x12) *
           -(lbl_803E466C * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4660) -
            lbl_803E4644);
      uStack_14 = FUN_80017760(0,0x19);
      local_30 = lbl_803E4644;
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar2 + 0x16) =
           *(float *)(psVar2 + 0x16) *
           -(lbl_803E466C * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4660) -
            lbl_803E4644);
      *(float *)(psVar2 + 0x14) = lbl_803E4670;
      local_2c = lbl_803E4650;
      local_28 = lbl_803E4650;
      local_24 = lbl_803E4650;
      local_38[2] = 0;
      local_38[1] = 0;
      uVar1 = FUN_80017760(0xffffd8f0,10000);
      local_38[0] = (ushort)uVar1;
      FUN_80017748(local_38,(float *)(psVar2 + 0x12));
      uVar1 = FUN_80017730();
      iVar3 = (int)*psVar2 - (uVar1 & 0xffff);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *psVar2 = (short)iVar3;
      break;
    case '\x02':
      puVar4 = FUN_80017aa4(0x24,0x3d4);
      uVar1 = FUN_80017760(0xffffff81,0x7e);
      *(char *)(puVar4 + 0xc) = (char)uVar1;
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0xd] = 400;
      psVar2 = (short *)FUN_80017ae4(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar4,5,*(undefined *)(param_9 + 0xac),0xffffffff,
                                     *(uint **)(param_9 + 0x30),param_14,param_15,param_16);
      *(float *)(psVar2 + 0x12) = *(float *)(param_9 + 0xc) - *(float *)(param_10 + 0xc);
      *(float *)(psVar2 + 0x16) = *(float *)(param_9 + 0x14) - *(float *)(param_10 + 0x14);
      dVar6 = (double)(*(float *)(psVar2 + 0x12) * *(float *)(psVar2 + 0x12) +
                      *(float *)(psVar2 + 0x16) * *(float *)(psVar2 + 0x16));
      if (dVar6 != (double)lbl_803E4650) {
        dVar6 = FUN_80293900(dVar6);
        *(float *)(psVar2 + 0x12) = (float)((double)*(float *)(psVar2 + 0x12) / dVar6);
        *(float *)(psVar2 + 0x16) = (float)((double)*(float *)(psVar2 + 0x16) / dVar6);
      }
      uStack_14 = FUN_80017760(0,0x19);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar2 + 0x12) =
           *(float *)(psVar2 + 0x12) *
           -(lbl_803E466C * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4660) -
            lbl_803E4644);
      uStack_1c = FUN_80017760(0,0x19);
      local_30 = lbl_803E4644;
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar2 + 0x16) =
           *(float *)(psVar2 + 0x16) *
           -(lbl_803E466C * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4660) -
            lbl_803E4644);
      *(float *)(psVar2 + 0x14) = lbl_803E4670;
      local_2c = lbl_803E4650;
      local_28 = lbl_803E4650;
      local_24 = lbl_803E4650;
      local_38[2] = 0;
      local_38[1] = 0;
      uVar1 = FUN_80017760(0xffffd8f0,10000);
      local_38[0] = (ushort)uVar1;
      FUN_80017748(local_38,(float *)(psVar2 + 0x12));
      uVar1 = FUN_80017730();
      iVar3 = (int)*psVar2 - (uVar1 & 0xffff);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *psVar2 = (short)iVar3;
      break;
    case '\x03':
      puVar4 = FUN_80017aa4(0x24,0x3d5);
      uVar1 = FUN_80017760(0xffffff81,0x7e);
      *(char *)(puVar4 + 0xc) = (char)uVar1;
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0xd] = 2000;
      psVar2 = (short *)FUN_80017ae4(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar4,5,*(undefined *)(param_9 + 0xac),0xffffffff,
                                     *(uint **)(param_9 + 0x30),param_14,param_15,param_16);
      *(float *)(psVar2 + 0x12) = *(float *)(param_9 + 0xc) - *(float *)(param_10 + 0xc);
      *(float *)(psVar2 + 0x16) = *(float *)(param_9 + 0x14) - *(float *)(param_10 + 0x14);
      dVar6 = (double)(*(float *)(psVar2 + 0x12) * *(float *)(psVar2 + 0x12) +
                      *(float *)(psVar2 + 0x16) * *(float *)(psVar2 + 0x16));
      if (dVar6 != (double)lbl_803E4650) {
        dVar6 = FUN_80293900(dVar6);
        *(float *)(psVar2 + 0x12) = (float)((double)*(float *)(psVar2 + 0x12) / dVar6);
        *(float *)(psVar2 + 0x16) = (float)((double)*(float *)(psVar2 + 0x16) / dVar6);
      }
      uStack_14 = FUN_80017760(0,0x19);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar2 + 0x12) =
           *(float *)(psVar2 + 0x12) *
           -(lbl_803E466C * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4660) -
            lbl_803E4644);
      uStack_1c = FUN_80017760(0,0x19);
      local_30 = lbl_803E4644;
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar2 + 0x16) =
           *(float *)(psVar2 + 0x16) *
           -(lbl_803E466C * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4660) -
            lbl_803E4644);
      *(float *)(psVar2 + 0x14) = lbl_803E4670;
      local_2c = lbl_803E4650;
      local_28 = lbl_803E4650;
      local_24 = lbl_803E4650;
      local_38[2] = 0;
      local_38[1] = 0;
      uVar1 = FUN_80017760(0xffffd8f0,10000);
      local_38[0] = (ushort)uVar1;
      FUN_80017748(local_38,(float *)(psVar2 + 0x12));
      uVar1 = FUN_80017730();
      iVar3 = (int)*psVar2 - (uVar1 & 0xffff);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *psVar2 = (short)iVar3;
      break;
    case '\x05':
    case '\x06':
      if (*(char *)(param_11 + 0x11) == '\x05') {
        puVar4 = FUN_80017aa4(0x30,0xb);
      }
      else {
        puVar4 = FUN_80017aa4(0x30,0x3cd);
      }
      *(undefined *)(puVar4 + 0xd) = 0x14;
      puVar4[0x16] = 0xffff;
      puVar4[0xe] = 0xffff;
      *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
      dVar6 = (double)lbl_803E4658;
      *(float *)(puVar4 + 6) = (float)(dVar6 + (double)*(float *)(param_9 + 0x10));
      *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
      puVar4[0x12] = 0xffff;
      iVar3 = FUN_80017ae4(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           param_14,param_15,param_16);
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x2c))
                ((double)lbl_803E4650,(double)lbl_803E4644,(double)lbl_803E4650);
      break;
    case '\a':
    case '\b':
      FUN_80017698((int)*(short *)(param_11 + 0xe),1);
      break;
    case '\t':
      uVar1 = FUN_80017ae8();
      if ((uVar1 & 0xff) != 0) {
        puVar4 = FUN_80017aa4(0x24,0x259);
        *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
        dVar6 = (double)lbl_803E4640;
        *(float *)(puVar4 + 6) = (float)(dVar6 + (double)*(float *)(param_9 + 0x10));
        *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
        *(undefined *)(puVar4 + 2) = 4;
        *(undefined *)(puVar4 + 3) = 200;
        puVar4[0x10] = 0xffff;
        puVar4[0xd] = 0x7f;
        FUN_80017ae4(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                     *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),param_14,
                     param_15,param_16);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80183c74
 * EN v1.0 Address: 0x80183C74
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8018405C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80183c74(int param_1)
{
  if (*(short *)(param_1 + 0xb4) != -1) {
    (**(code **)(*DAT_803dd6d0 + 0x4c))();
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80183cb8
 * EN v1.0 Address: 0x80183CB8
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801840AC
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80183cb8(void)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  FUN_80006b0c(DAT_803de748);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80183cf4
 * EN v1.0 Address: 0x80183CF4
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x801840E4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80183cf4(void)
{
  short sVar1;
  int iVar2;
  int iVar3;
  char in_r8;
  int iVar4;
  
  iVar2 = FUN_80286838();
  iVar4 = *(int *)(iVar2 + 0xb8);
  iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(*(int *)(iVar2 + 0x4c) + 0x14));
  if ((iVar3 == 0) ||
     (((sVar1 = *(short *)(iVar4 + 8), sVar1 != 0 && (sVar1 < 0x33)) ||
      (lbl_803E4650 < *(float *)(iVar4 + 4))))) {
    *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
  }
  else {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      if (in_r8 == '\0') {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        goto LAB_801841d8;
      }
    }
    else if (in_r8 != -1) {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      goto LAB_801841d8;
    }
    FUN_8003b818(iVar2);
  }
LAB_801841d8:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: largecrate_getExtraSize
 * EN v1.0 Address: 0x80183B44
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80183F3C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int largecrate_getExtraSize(void)
{
  return 0x2c;
}

/*
 * --INFO--
 *
 * Function: largecrate_func08
 * EN v1.0 Address: 0x80183B4C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80183F44
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int largecrate_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: largecrate_hitDetect
 * EN v1.0 Address: 0x80183C98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80184090
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void largecrate_hitDetect(void)
{
}
