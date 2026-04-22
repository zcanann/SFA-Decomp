#include "ghidra_import.h"
#include "main/dll/CR/CRsnowClaw.h"

extern undefined4 FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_800372f8();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern f64 DOUBLE_803e6518;
extern f32 FLOAT_803e64c8;
extern f32 FLOAT_803e64d0;
extern f32 FLOAT_803e6504;
extern f32 FLOAT_803e6508;
extern f32 FLOAT_803e650c;
extern f32 FLOAT_803e6510;

/*
 * --INFO--
 *
 * Function: FUN_801e383c
 * EN v1.0 Address: 0x801E383C
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e383c(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_800372f8(param_1,3);
  FUN_80037a5c(param_1,10);
  *(undefined *)(iVar1 + 4) = 4;
  *(float *)(iVar1 + 0xc) = *(float *)(iVar1 + 0xc) + FLOAT_803e64c8;
  *(float *)(iVar1 + 8) = *(float *)(iVar1 + 8) + FLOAT_803e64d0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e38c0
 * EN v1.0 Address: 0x801E38C0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e38c0(int param_1)
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
 * Function: FUN_801e38f4
 * EN v1.0 Address: 0x801E38F4
 * EN v1.0 Size: 288b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e38f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  double dVar3;
  
  fVar1 = FLOAT_803e6504;
  if (*(int *)(param_9 + 0x30) != 0) {
    iVar2 = *(int *)(*(int *)(param_9 + 0x30) + 0xf4);
    dVar3 = (double)FLOAT_803e6504;
    *(float *)(param_9 + 0xc) = FLOAT_803e6504;
    *(float *)(param_9 + 0x10) = fVar1;
    *(float *)(param_9 + 0x14) = fVar1;
    if (*(short *)(*(int *)(param_9 + 0x30) + 0x46) == 0x139) {
      if ((iVar2 < 10) || (0xc < iVar2)) {
        if (*(short *)(param_9 + 0xa0) != 1) {
          FUN_8003042c((double)FLOAT_803e6504,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,1,0,param_12,param_13,param_14,param_15,param_16);
        }
        dVar3 = (double)FLOAT_803e6510;
      }
      else {
        if (*(short *)(param_9 + 0xa0) != 0) {
          FUN_8003042c(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,
                       param_12,param_13,param_14,param_15,param_16);
        }
        if (iVar2 < 0xc) {
          dVar3 = (double)FLOAT_803e650c;
        }
        else {
          dVar3 = (double)FLOAT_803e6508;
        }
      }
    }
    else {
      if (*(short *)(param_9 + 0xa0) != 1) {
        FUN_8003042c(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,
                     param_12,param_13,param_14,param_15,param_16);
      }
      dVar3 = (double)FLOAT_803e6510;
    }
    FUN_8002fb40(dVar3,(double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) -
                                      DOUBLE_803e6518));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e3a14
 * EN v1.0 Address: 0x801E3A14
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e3a14(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}
