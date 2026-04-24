// Function: FUN_80152498
// Entry: 80152498
// Size: 60 bytes

void FUN_80152498(uint param_1,int param_2)

{
  FUN_8000bb38(param_1,0x23);
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
  return;
}

