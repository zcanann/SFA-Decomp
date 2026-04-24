// Function: FUN_80154c24
// Entry: 80154c24
// Size: 232 bytes

void FUN_80154c24(int param_1,int param_2)

{
  float fVar1;
  undefined uVar3;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e29e8;
  *(undefined4 *)(param_2 + 0x2e4) = 0x8000009;
  *(float *)(param_2 + 0x308) = FLOAT_803e29d0;
  *(float *)(param_2 + 0x300) = FLOAT_803e29b4;
  *(float *)(param_2 + 0x304) = FLOAT_803e29ec;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e29f0;
  *(float *)(param_2 + 0x314) = FLOAT_803e29f0;
  *(undefined *)(param_2 + 0x321) = 1;
  *(float *)(param_2 + 0x318) = FLOAT_803e2994;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  fVar1 = FLOAT_803e2990;
  *(float *)(param_2 + 0x324) = FLOAT_803e2990;
  *(float *)(param_2 + 0x328) = fVar1;
  *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_1 + 0x10);
  uVar3 = FUN_800221a0(0,0xff);
  *(undefined *)(param_2 + 0x33a) = uVar3;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x330) = FLOAT_803e29f4;
  uVar2 = FUN_800221a0(0x32,0x4b);
  *(float *)(param_2 + 0x2fc) =
       FLOAT_803e29f8 * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e29a8);
  return;
}

