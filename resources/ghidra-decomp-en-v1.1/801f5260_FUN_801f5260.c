// Function: FUN_801f5260
// Entry: 801f5260
// Size: 300 bytes

void FUN_801f5260(int param_1,int param_2)

{
  uint uVar1;
  
  *(undefined4 *)(param_2 + 4) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x24) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x18) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x28) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x2c) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x20) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x30) = *(undefined4 *)(param_1 + 0x14);
  *(float *)(param_2 + 0x44) = FLOAT_803e6b44;
  *(float *)(param_2 + 0x48) = FLOAT_803e6b48;
  *(float *)(param_2 + 0x40) = FLOAT_803e6b4c;
  *(undefined *)(param_2 + 0x68) = 0;
  *(undefined *)(param_2 + 0x67) = 0;
  uVar1 = FUN_80022264(500,0x5dc);
  *(short *)(param_2 + 0x62) = (short)uVar1;
  uVar1 = FUN_80022264(0,65000);
  *(short *)(param_2 + 0x60) = (short)uVar1;
  *(undefined2 *)(param_2 + 100) = 0x3c;
  *(undefined *)(param_2 + 0x66) = 4;
  *(float *)(param_2 + 0x4c) = FLOAT_803e6b50;
  *(float *)(param_2 + 0x50) = FLOAT_803e6b54;
  *(undefined4 *)(param_2 + 0x54) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x58) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x5c) = *(undefined4 *)(param_1 + 0x14);
  *(undefined *)(param_2 + 0x6b) = 1;
  *(float *)(param_2 + 0x78) = FLOAT_803e6b58;
  return;
}

