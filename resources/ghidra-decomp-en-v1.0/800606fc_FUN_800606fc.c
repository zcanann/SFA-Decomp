// Function: FUN_800606fc
// Entry: 800606fc
// Size: 16 bytes

int FUN_800606fc(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x68) + param_2 * 0x1c;
}

