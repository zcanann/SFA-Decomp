// Function: FUN_801ffd7c
// Entry: 801ffd7c
// Size: 148 bytes

void FUN_801ffd7c(int param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar4 + 8) = 5;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  fVar1 = FLOAT_803e627c;
  *(float *)(param_1 + 0x2c) = FLOAT_803e627c;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = FLOAT_803e62a0;
  uVar2 = FUN_800221a0(0,0xffff);
  *(undefined4 *)(iVar4 + 4) = uVar2;
  iVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x20));
  if (iVar3 != 0) {
    *(undefined *)(iVar4 + 8) = 4;
  }
  return;
}

