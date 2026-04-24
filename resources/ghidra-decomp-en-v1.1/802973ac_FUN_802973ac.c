// Function: FUN_802973ac
// Entry: 802973ac
// Size: 16 bytes

byte FUN_802973ac(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 1 & 1;
}

