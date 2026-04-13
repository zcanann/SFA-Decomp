// Function: FUN_801f5504
// Entry: 801f5504
// Size: 188 bytes

void FUN_801f5504(undefined4 param_1,int param_2)

{
  uint uVar1;
  
  *(undefined4 *)(param_2 + 4) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(param_2 + 0x18);
  *(undefined4 *)(param_2 + 0x24) = *(undefined4 *)(param_2 + 0x28);
  *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_2 + 0x18) = *(undefined4 *)(param_2 + 0x1c);
  *(undefined4 *)(param_2 + 0x28) = *(undefined4 *)(param_2 + 0x2c);
  *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_2 + 0x1c) = *(undefined4 *)(param_2 + 0x20);
  *(undefined4 *)(param_2 + 0x2c) = *(undefined4 *)(param_2 + 0x30);
  uVar1 = FUN_80022264(0xa0,0xb4);
  *(float *)(param_2 + 0x44) =
       FLOAT_803e6b70 * (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6b68);
  *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(param_2 + 0x34);
  *(undefined4 *)(param_2 + 0x20) = *(undefined4 *)(param_2 + 0x38);
  *(undefined4 *)(param_2 + 0x30) = *(undefined4 *)(param_2 + 0x3c);
  return;
}

