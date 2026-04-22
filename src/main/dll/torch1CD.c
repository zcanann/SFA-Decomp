#include "ghidra_import.h"
#include "main/dll/torch1CD.h"

extern undefined8 FUN_80008cbc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern uint FUN_80020078();
extern undefined8 FUN_800201ac();
extern void* FUN_8002becc();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80056818();
extern undefined4 FUN_801caf74();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc270;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd6fc;
extern undefined4 DAT_803de860;

/*
 * --INFO--
 *
 * Function: FUN_801cbbe8
 * EN v1.0 Address: 0x801CBBE8
 * EN v1.0 Size: 392b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cbbe8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801cbd70
 * EN v1.0 Address: 0x801CBD70
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cbd70(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cbda4
 * EN v1.0 Address: 0x801CBDA4
 * EN v1.0 Size: 680b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cbda4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
  uVar1 = FUN_80020078(0x5b9);
  if (uVar1 == 0) {
    if ((*(int *)(param_9 + 0x7c) == 0) &&
       (uVar1 = FUN_80020078((int)*(char *)(iVar5 + 0x1f) + 0x1cd), uVar1 != 0)) {
      piVar2 = (int *)FUN_80013ee8(0x82);
      (**(code **)(*piVar2 + 4))(param_9,0,0,1,0xffffffff,0);
      in_r8 = 0;
      in_r9 = *piVar2;
      (**(code **)(in_r9 + 4))(param_9,1,0,1,0xffffffff);
      param_1 = FUN_8000bb38((uint)param_9,0xaf);
      FUN_80013e4c((undefined *)piVar2);
      psVar4[1] = 1;
      *(undefined4 *)(param_9 + 0x7c) = 1;
    }
    if (psVar4[1] != 0) {
      *psVar4 = *psVar4 - psVar4[1] * (ushort)DAT_803dc070;
    }
    if ((*psVar4 < 1) && (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
      puVar3 = FUN_8002becc(0x38,0x2d0);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x10);
      *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
      *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
      *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
      *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
      *(undefined *)((int)puVar3 + 0x27) = 1;
      puVar3[0xc] = 0x1e7;
      puVar3[0x18] = 0xffff;
      *(char *)(puVar3 + 0x15) = (char)((ushort)*param_9 >> 8);
      *(undefined *)((int)puVar3 + 0x2b) = 2;
      uVar1 = FUN_80020078(0x1ce);
      if (uVar1 == 0) {
        puVar3[0x11] = 0xffff;
      }
      else {
        puVar3[0x11] = 0x49;
      }
      *(undefined *)((int)puVar3 + 0x29) = 0xff;
      *(undefined *)(puVar3 + 0x17) = 0xff;
      *(undefined *)(puVar3 + 0x19) = *(undefined *)(iVar5 + 0x1f);
      iVar5 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                           *(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),
                           in_r8,in_r9,in_r10);
      if ((iVar5 != 0) && (*(int *)(iVar5 + 0xb8) != 0)) {
        *(undefined *)(*(int *)(iVar5 + 0xb8) + 0x404) = 0x20;
      }
      *psVar4 = 100;
      psVar4[1] = 0;
    }
  }
  else {
    *(undefined4 *)(param_9 + 0x7c) = 0;
    *psVar4 = 100;
    psVar4[1] = 0;
    *(undefined *)((int)param_9 + 0x37) = 0xff;
    *(undefined *)(param_9 + 0x1b) = 0xff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cc04c
 * EN v1.0 Address: 0x801CC04C
 * EN v1.0 Size: 652b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cc04c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  iVar1 = FUN_80286840();
  iVar3 = *(int *)(iVar1 + 0xb8);
  *(undefined2 *)(param_11 + 0x6e) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  uVar4 = extraout_f1;
  if (*(short *)(iVar3 + 10) != 0) {
    *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) + *(short *)(iVar3 + 10);
    if ((*(short *)(iVar3 + 8) < 2) && (*(short *)(iVar3 + 10) < 1)) {
      *(undefined2 *)(iVar3 + 8) = 1;
      *(undefined2 *)(iVar3 + 10) = 0;
    }
    else if ((0x45 < *(short *)(iVar3 + 8)) && (-1 < *(short *)(iVar3 + 10))) {
      *(undefined2 *)(iVar3 + 8) = 0x46;
      *(undefined2 *)(iVar3 + 10) = 0;
    }
    uVar4 = (**(code **)(*DAT_803dd6f0 + 0x38))(3,*(ushort *)(iVar3 + 8) & 0xff);
  }
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
    switch(*(undefined *)(param_11 + iVar2 + 0x81)) {
    case 1:
      uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                           ,0xc3,0,param_13,param_14,param_15,param_16);
      break;
    case 2:
      if (DAT_803dc270 == 0xffffffff) {
        uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,0x14,0,param_13,param_14,param_15,param_16);
      }
      else {
        uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,DAT_803dc270 & 0xffff,0,param_13,param_14,param_15,param_16);
      }
      break;
    case 3:
      *(undefined *)(iVar3 + 0x14) = 1;
      break;
    case 4:
      *(undefined *)(iVar3 + 0x13) = 4;
      *(undefined *)(iVar3 + 0x14) = 2;
      FUN_800201ac(0x129,1);
      FUN_800201ac(0x1d2,0);
      uVar4 = FUN_800201ac(0x126,1);
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      break;
    case 5:
      *(undefined *)(iVar3 + 0x13) = 6;
      *(undefined *)(iVar3 + 0x14) = 3;
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      uVar4 = FUN_800201ac(0x129,1);
      break;
    case 6:
      uVar4 = FUN_800201ac(0x1d2,1);
      break;
    case 7:
      uVar4 = FUN_800201ac(0x1d2,0);
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      break;
    case 8:
      uVar4 = FUN_800201ac(0x127,1);
      break;
    case 9:
      uVar4 = FUN_800201ac(0x128,1);
      if (DAT_803de860 == 0) {
        DAT_803de860 = FUN_80056818();
      }
      break;
    case 0xb:
      *(undefined2 *)(iVar3 + 8) = 100;
      param_13 = 0;
      param_14 = *DAT_803dd6f0;
      uVar4 = (**(code **)(param_14 + 0x18))(3,0x2d,0x50,*(ushort *)(iVar3 + 8) & 0xff);
    }
    *(undefined *)(param_11 + iVar2 + 0x81) = 0;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cc2d8
 * EN v1.0 Address: 0x801CC2D8
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cc2d8(void)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cc308
 * EN v1.0 Address: 0x801CC308
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cc308(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}
