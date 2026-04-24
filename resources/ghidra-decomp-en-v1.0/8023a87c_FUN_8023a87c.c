// Function: FUN_8023a87c
// Entry: 8023a87c
// Size: 248 bytes

void FUN_8023a87c(undefined4 param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  fVar1 = FLOAT_803e74d4;
  iVar3 = *(int *)(param_2 + 0x10);
  if (iVar3 == 0) {
    if (*(float *)(param_2 + 0x6c) < FLOAT_803e74d4) {
      iVar3 = FUN_8001ffb4(0x12);
      if (iVar3 != 0) {
        uVar2 = FUN_800221a0(1,0x14);
        *(float *)(param_2 + 0x6c) =
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e7498);
        FUN_800200e8(0x12,0);
      }
    }
    else {
      *(float *)(param_2 + 0x6c) = *(float *)(param_2 + 0x6c) - FLOAT_803db414;
      if (*(float *)(param_2 + 0x6c) < fVar1) {
        FUN_80239dd8();
      }
    }
  }
  else {
    *(float *)(iVar3 + 0x14) = *(float *)(iVar3 + 0x14) - FLOAT_803e74d8;
    *(uint *)(param_2 + 0x90) = *(int *)(param_2 + 0x90) - (uint)DAT_803db410;
    if (*(int *)(param_2 + 0x90) < 0) {
      FUN_8022f558(*(undefined4 *)(param_2 + 0x10),5);
      *(undefined4 *)(param_2 + 0x90) = 0;
      *(undefined4 *)(param_2 + 0x10) = 0;
    }
  }
  return;
}

