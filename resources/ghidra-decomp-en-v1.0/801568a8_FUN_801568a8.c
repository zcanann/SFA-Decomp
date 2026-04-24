// Function: FUN_801568a8
// Entry: 801568a8
// Size: 168 bytes

void FUN_801568a8(undefined4 param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2ae8;
  *(undefined4 *)(param_2 + 0x2e4) = 0x2002b029;
  *(float *)(param_2 + 0x308) = FLOAT_803e2acc;
  *(float *)(param_2 + 0x300) = FLOAT_803e2aec;
  *(float *)(param_2 + 0x304) = FLOAT_803e2af0;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e2af4;
  *(float *)(param_2 + 0x314) = FLOAT_803e2af4;
  *(undefined *)(param_2 + 0x321) = 1;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 2;
  *(float *)(param_2 + 0x31c) = fVar1;
  uVar2 = FUN_800221a0(0x78,0x1e0);
  *(float *)(param_2 + 0x328) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2aa0);
  return;
}

