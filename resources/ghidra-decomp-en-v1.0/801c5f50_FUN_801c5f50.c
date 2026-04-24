// Function: FUN_801c5f50
// Entry: 801c5f50
// Size: 172 bytes

void FUN_801c5f50(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  FUN_8000a518(0xd8,0);
  FUN_8000a518(0xd9,0);
  FUN_8000a518(8,0);
  FUN_8000a518(0xd,0);
  if (*piVar1 != 0) {
    FUN_8001f384();
    *piVar1 = 0;
  }
  FUN_80036fa4(param_1,0xb);
  FUN_800200e8(0xefa,0);
  FUN_800200e8(0xcbb,1);
  FUN_800200e8(0xa7f,1);
  return;
}

