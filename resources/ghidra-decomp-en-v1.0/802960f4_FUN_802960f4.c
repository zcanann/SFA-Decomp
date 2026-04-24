// Function: FUN_802960f4
// Entry: 802960f4
// Size: 24 bytes

void FUN_802960f4(int param_1,int *param_2)

{
  if (param_2 == (int *)0x0) {
    return;
  }
  *param_2 = *(int *)(param_1 + 0xb8) + 0x3c4;
  return;
}

