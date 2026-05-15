#include "ghidra_import.h"
#include "main/dll/mmshrine/animobj1C0.h"

extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern int FUN_800632f4();
extern undefined4 FUN_80135814();
extern double FUN_80194a70();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd718;
extern f64 DOUBLE_803e5c08;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C10;
extern f32 lbl_803E5C18;
extern f32 lbl_803E5C1C;
extern f32 lbl_803E5C20;

/*
 * --INFO--
 *
 * Function: FUN_801c5990
 * EN v1.0 Address: 0x801C5990
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x801C5B9C
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5990(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  *(undefined2 *)(iVar5 + 0x6a) = *(undefined2 *)(param_10 + 0x1a);
  *(undefined2 *)(iVar5 + 0x6e) = 0xffff;
  dVar6 = DOUBLE_803e5c08;
  dVar7 = (double)lbl_803E5C00;
  *(float *)(iVar5 + 0x24) =
       (float)(dVar7 / (double)(float)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,
                                                                                (uint)*(byte *)(
                                                  param_10 + 0x24)) - DOUBLE_803e5c08)));
  *(undefined4 *)(iVar5 + 0x28) = 0xffffffff;
  iVar4 = *(int *)(param_9 + 0xf4);
  if ((iVar4 == 0) && (*(short *)(param_10 + 0x18) != 1)) {
    dVar6 = (double)(**(code **)(*DAT_803dd6d4 + 0x1c))(iVar5);
    *(int *)(param_9 + 0xf4) = *(short *)(param_10 + 0x18) + 1;
  }
  else if ((iVar4 != 0) && ((int)*(short *)(param_10 + 0x18) != iVar4 + -1)) {
    dVar6 = (double)(**(code **)(*DAT_803dd6d4 + 0x24))(iVar5);
    if (*(short *)(param_10 + 0x18) != -1) {
      dVar6 = (double)(**(code **)(*DAT_803dd6d4 + 0x1c))(iVar5,param_10);
    }
    *(int *)(param_9 + 0xf4) = *(short *)(param_10 + 0x18) + 1;
  }
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x24,0x1b8);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = 0x20;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    uVar3 = FUN_80017ae4(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 200) = uVar3;
    *(float *)(*(int *)(param_9 + 200) + 8) =
         *(float *)(*(int *)(param_9 + 200) + 8) * lbl_803E5C10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c5c2c
 * EN v1.0 Address: 0x801C5C2C
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x801C5D64
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5c2c(int param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  double in_f31;
  undefined4 *local_28 [4];
  
  iVar5 = *(int *)(param_1 + 0x4c);
  ObjHits_SetHitVolumeSlot(param_1,9,1,0);
  iVar3 = FUN_80017af8(*(int *)(param_1 + 0xf8));
  if (iVar3 == 0) {
    FUN_80135814();
    iVar3 = FUN_800632f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,local_28,0,0);
    if ((iVar3 != 0) && (in_f31 = (double)lbl_803E5C18, 0 < iVar3)) {
      do {
        if ((*(char *)((float *)*local_28[0] + 5) == '\x0e') &&
           (dVar6 = (double)(*(float *)*local_28[0] - *(float *)(param_1 + 0x10)), in_f31 < dVar6))
        {
          in_f31 = dVar6;
        }
        local_28[0] = local_28[0] + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  else {
    dVar6 = FUN_80194a70(iVar3,3);
    in_f31 = (double)(float)(dVar6 - (double)*(float *)(param_1 + 0x10));
  }
  fVar1 = (float)((double)*(float *)(param_1 + 0x10) + in_f31);
  fVar2 = *(float *)(iVar5 + 0xc);
  if (fVar1 <= fVar2) {
    *(float *)(param_1 + 0x10) = fVar1;
    *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    if (*(int *)(param_1 + 0xf4) < 1) {
      uVar4 = randomGetRange(0x3c,0xf0);
      *(uint *)(param_1 + 0xf4) = uVar4;
      if ((double)lbl_803E5C1C == in_f31) {
        (**(code **)(*DAT_803dd718 + 0x14))
                  ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                   (double)*(float *)(param_1 + 0x14),(double)lbl_803E5C20,0,3);
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = fVar2;
  }
  return;
}
