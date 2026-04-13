// Function: FUN_8023af74
// Entry: 8023af74
// Size: 248 bytes

void FUN_8023af74(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  uint uVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  
  iVar2 = *(int *)(param_10 + 0x10);
  if (iVar2 == 0) {
    dVar4 = (double)*(float *)(param_10 + 0x6c);
    dVar3 = (double)FLOAT_803e816c;
    if (dVar4 < dVar3) {
      uVar1 = FUN_80020078(0x12);
      if (uVar1 != 0) {
        uVar1 = FUN_80022264(1,0x14);
        *(float *)(param_10 + 0x6c) =
             (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e8130);
        FUN_800201ac(0x12,0);
      }
    }
    else {
      *(float *)(param_10 + 0x6c) = (float)(dVar4 - (double)FLOAT_803dc074);
      if ((double)*(float *)(param_10 + 0x6c) < dVar3) {
        FUN_8023a4d0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
      }
    }
  }
  else {
    *(float *)(iVar2 + 0x14) = *(float *)(iVar2 + 0x14) - FLOAT_803e8170;
    *(uint *)(param_10 + 0x90) = *(int *)(param_10 + 0x90) - (uint)DAT_803dc070;
    if (*(int *)(param_10 + 0x90) < 0) {
      FUN_8022fc1c(*(int *)(param_10 + 0x10),5);
      *(undefined4 *)(param_10 + 0x90) = 0;
      *(undefined4 *)(param_10 + 0x10) = 0;
    }
  }
  return;
}

