// Function: FUN_801c2dd4
// Entry: 801c2dd4
// Size: 148 bytes

void FUN_801c2dd4(int param_1)

{
  undefined4 uVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (*piVar2 != 0) {
    FUN_8001f384();
    *piVar2 = 0;
  }
  FUN_8001467c();
  uVar1 = FUN_800481b0(0x1f);
  FUN_8004350c(uVar1,1,0);
  FUN_8000a518(0xd8,0);
  FUN_8000a518(0xd9,0);
  FUN_8000a518(8,0);
  FUN_800200e8(0xefa,0);
  FUN_800200e8(0xcbb,1);
  return;
}

