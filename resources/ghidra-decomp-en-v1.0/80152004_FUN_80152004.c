// Function: FUN_80152004
// Entry: 80152004
// Size: 60 bytes

void FUN_80152004(undefined4 param_1,int param_2)

{
  FUN_8000bb18(param_1,0x23);
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
  return;
}

