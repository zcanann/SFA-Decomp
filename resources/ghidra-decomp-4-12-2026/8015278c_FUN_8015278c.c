// Function: FUN_8015278c
// Entry: 8015278c
// Size: 144 bytes

void FUN_8015278c(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3490;
  *(float *)(param_2 + 0x2a8) = FLOAT_803e3494;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc80;
  *(float *)(param_2 + 0x308) = FLOAT_803e3498;
  *(float *)(param_2 + 0x300) = FLOAT_803e349c;
  *(float *)(param_2 + 0x304) = FLOAT_803e34a0;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e34a4;
  *(float *)(param_2 + 0x314) = FLOAT_803e34a4;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  if (*(char *)(iVar2 + 0x2e) != -1) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  return;
}

