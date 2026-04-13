// Function: FUN_800d8f94
// Entry: 800d8f94
// Size: 76 bytes

void FUN_800d8f94(uint param_1,int param_2,int param_3,int param_4,int param_5)

{
  if ((*(uint *)(param_2 + 0x314) & 1 << param_3) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & ~(1 << param_3);
    FUN_8000bb38(param_1,(ushort)*(undefined4 *)(param_5 + param_4 * 4));
  }
  return;
}

