#include "ghidra_import.h"
#include "main/dll/WM/deaddino.h"

extern undefined8 FUN_8000bb38();
extern void* FUN_8002becc();
extern undefined8 FUN_8002cc9c();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8002e1f4();
extern undefined8 FUN_80037da8();
extern undefined4 FUN_80037e24();
extern undefined4 FUN_8003b9ec();
extern undefined8 FUN_802371fc();

extern undefined4 DAT_803dc071;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern f64 DOUBLE_803e6280;
extern f32 FLOAT_803e6278;

/*
 * --INFO--
 *
 * Function: FUN_801dd270
 * EN v1.0 Address: 0x801DD270
 * EN v1.0 Size: 108b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd270(int param_1)
{
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dd6f4 + 8))(param_1,0xffff,0,0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dd2dc
 * EN v1.0 Address: 0x801DD2DC
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd2dc(int param_1)
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
 * Function: FUN_801dd310
 * EN v1.0 Address: 0x801DD310
 * EN v1.0 Size: 752b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd310(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  byte bVar1;
  int *piVar2;
  uint uVar3;
  undefined2 *puVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  int local_28;
  int local_24 [5];
  
  iVar8 = *(int *)(param_9 + 0x5c);
  if ((*(int *)(param_9 + 0x26) != 0) && (*(short *)(*(int *)(param_9 + 0x26) + 0x18) != -1)) {
    local_24[2] = (int)DAT_803dc071;
    local_24[1] = 0x43300000;
    local_24[0] = (**(code **)(*DAT_803dd6d4 + 0x14))
                            ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) -
                                            DOUBLE_803e6280));
    uVar10 = extraout_f1;
    if ((local_24[0] != 0) && (param_9[0x5a] == -2)) {
      iVar7 = (int)*(char *)(iVar8 + 0x57);
      iVar9 = 0;
      piVar2 = (int *)FUN_8002e1f4(local_24,&local_28);
      iVar6 = 0;
      for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar5 = *piVar2;
        if (*(short *)(iVar5 + 0xb4) == iVar7) {
          iVar9 = iVar5;
        }
        if (((*(short *)(iVar5 + 0xb4) == -2) && (*(short *)(iVar5 + 0x44) == 0x10)) &&
           (iVar8 = *(int *)(iVar5 + 0xb8), iVar7 == *(char *)(iVar8 + 0x57))) {
          iVar6 = iVar6 + 1;
        }
        piVar2 = piVar2 + 1;
      }
      if (((iVar6 < 2) && (iVar9 != 0)) && (*(short *)(iVar9 + 0xb4) != -1)) {
        *(undefined2 *)(iVar9 + 0xb4) = 0xffff;
        uVar10 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar7);
      }
      param_9[0x5a] = -1;
    }
    for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)(iVar8 + 0x8b); iVar9 = iVar9 + 1) {
      bVar1 = *(byte *)(iVar8 + iVar9 + 0x81);
      if (bVar1 == 1) {
        if (*(int *)(param_9 + 100) != 0) {
          uVar10 = FUN_802371fc(*(int *)(param_9 + 100),'\0');
        }
      }
      else if (bVar1 == 0) {
        if ((*(int *)(param_9 + 100) == 0) && (uVar3 = FUN_8002e144(), (uVar3 & 0xff) != 0)) {
          puVar4 = FUN_8002becc(0x30,0x6e8);
          *(undefined *)((int)puVar4 + 0x1b) = 9;
          *(undefined *)(puVar4 + 0xe) = 0;
          *(undefined *)((int)puVar4 + 0x1d) = 0;
          *(float *)(puVar4 + 0x10) = FLOAT_803e6278;
          *(undefined *)(puVar4 + 0x13) = 0xff;
          *(undefined *)((int)puVar4 + 0x27) = 0xff;
          *(undefined *)(puVar4 + 0x14) = 0xff;
          puVar4[0x12] = 0xffff;
          *(undefined *)(puVar4 + 2) = 2;
          *(undefined *)((int)puVar4 + 5) = 1;
          *(undefined *)(puVar4 + 3) = 0xff;
          *(undefined *)((int)puVar4 + 7) = 0xff;
          *(undefined *)((int)puVar4 + 0x29) = 1;
          *(undefined *)(puVar4 + 0x15) = 0;
          iVar6 = FUN_8002e088(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4
                               ,5,*(undefined *)(param_9 + 0x56),0xffffffff,
                               *(uint **)(param_9 + 0x18),in_r8,in_r9,in_r10);
          *(ushort *)(iVar6 + 6) = *(ushort *)(iVar6 + 6) | 0x4000;
          FUN_80037e24((int)param_9,iVar6,0);
          uVar10 = FUN_8000bb38((uint)param_9,0x10f);
        }
      }
      else if ((bVar1 < 3) && (iVar6 = *(int *)(param_9 + 100), iVar6 != 0)) {
        uVar10 = FUN_80037da8((int)param_9,iVar6);
        uVar10 = FUN_8002cc9c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar6);
      }
    }
    if (*(int *)(param_9 + 100) != 0) {
      *(short *)(*(int *)(param_9 + 100) + 4) = param_9[2];
      *(short *)(*(int *)(param_9 + 100) + 2) = param_9[1] + 0xe38;
      **(short **)(param_9 + 100) = *param_9 + -0x8000;
    }
  }
  return;
}
