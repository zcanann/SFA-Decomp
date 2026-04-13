// Function: FUN_80028438
// Entry: 80028438
// Size: 16 bytes

int FUN_80028438(int param_1,int param_2)

{
  return *(int *)(param_1 + 0xd0) + param_2 * 0x1c;
}

