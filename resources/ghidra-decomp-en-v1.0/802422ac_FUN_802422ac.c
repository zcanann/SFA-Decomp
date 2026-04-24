// Function: FUN_802422ac
// Entry: 802422ac
// Size: 92 bytes

void FUN_802422ac(uint param_1)

{
  DAT_800000c0 = param_1 & 0x3fffffff;
  DAT_800000d4 = param_1;
  if (DAT_800000d8 == param_1) {
    *(uint *)(param_1 + 0x19c) = *(uint *)(param_1 + 0x19c) | 0x2000;
    return;
  }
  *(uint *)(param_1 + 0x19c) = *(uint *)(param_1 + 0x19c) & 0xffffdfff;
  instructionSynchronize();
  return;
}

