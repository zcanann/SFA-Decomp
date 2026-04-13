// Function: FUN_8002b9a0
// Entry: 8002b9a0
// Size: 40 bytes

void FUN_8002b9a0(int param_1,char param_2)

{
  if ((param_2 == 'Z') && ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 0x40) == 0)) {
    return;
  }
  *(char *)(param_1 + 0xae) = param_2;
  return;
}

