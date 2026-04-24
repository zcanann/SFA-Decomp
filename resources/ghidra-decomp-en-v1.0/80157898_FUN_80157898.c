// Function: FUN_80157898
// Entry: 80157898
// Size: 240 bytes

void FUN_80157898(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  
  uVar4 = (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x2f);
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e2b58);
  if (FLOAT_803e2b18 == (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e2b58)) {
    fVar1 = FLOAT_803e2b38;
  }
  fVar1 = fVar1 / FLOAT_803e2b38;
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2b64;
  *(undefined4 *)(param_2 + 0x2e4) = 0x8b;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
  *(float *)(param_2 + 0x308) = FLOAT_803e2b68 * fVar1;
  fVar2 = FLOAT_803e2b40;
  *(float *)(param_2 + 0x300) = FLOAT_803e2b40;
  *(float *)(param_2 + 0x304) = FLOAT_803e2b6c;
  *(undefined *)(param_2 + 800) = 0;
  *(float *)(param_2 + 0x314) = FLOAT_803e2b70;
  *(undefined *)(param_2 + 0x321) = 3;
  fVar3 = FLOAT_803e2b4c;
  *(float *)(param_2 + 0x318) = FLOAT_803e2b4c;
  *(undefined *)(param_2 + 0x322) = 5;
  *(float *)(param_2 + 0x31c) = fVar3;
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(float *)(param_2 + 0x324) = FLOAT_803e2b74;
  *(float *)(param_2 + 0x328) = fVar2;
  *(undefined *)(param_1 + 0x36) = 0;
  *(float *)(param_2 + 0x2fc) = FLOAT_803e2b78 * fVar1;
  *(undefined4 *)(param_2 + 0x2e8) = 0;
  FUN_80035f20();
  return;
}

