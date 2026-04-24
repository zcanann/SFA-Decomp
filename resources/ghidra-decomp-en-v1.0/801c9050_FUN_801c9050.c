// Function: FUN_801c9050
// Entry: 801c9050
// Size: 164 bytes

void FUN_801c9050(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_8001f384();
    *piVar1 = 0;
  }
  FUN_8001467c();
  FUN_80036fa4(param_1,0xb);
  FUN_8000a518(0xd8,0);
  FUN_8000a518(0xd9,0);
  FUN_8000a518(8,0);
  FUN_8000a518(0xe,0);
  FUN_800200e8(0xefa,0);
  FUN_800200e8(0xcbb,1);
  return;
}

