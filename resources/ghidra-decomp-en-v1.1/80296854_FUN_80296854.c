// Function: FUN_80296854
// Entry: 80296854
// Size: 24 bytes

void FUN_80296854(int param_1,int *param_2)

{
  if (param_2 == (int *)0x0) {
    return;
  }
  *param_2 = *(int *)(param_1 + 0xb8) + 0x3c4;
  return;
}

