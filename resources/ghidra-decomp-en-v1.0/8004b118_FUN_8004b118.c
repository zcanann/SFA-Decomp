// Function: FUN_8004b118
// Entry: 8004b118
// Size: 48 bytes

undefined4 FUN_8004b118(int param_1)

{
  short sVar1;
  
  sVar1 = *(short *)(param_1 + 0x2c);
  if ((int)sVar1 < (int)*(short *)(param_1 + 0x2a)) {
    *(short *)(param_1 + 0x2c) = sVar1 + 1;
    return *(undefined4 *)(*(int *)(param_1 + 8) + sVar1 * 4);
  }
  return 0;
}

