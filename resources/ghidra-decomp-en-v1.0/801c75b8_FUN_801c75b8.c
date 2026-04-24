// Function: FUN_801c75b8
// Entry: 801c75b8
// Size: 176 bytes

void FUN_801c75b8(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  if (*piVar3 != 0) {
    FUN_8001f384();
    *piVar3 = 0;
  }
  FUN_8001467c();
  FUN_80036fa4(param_1,0xb);
  FUN_8000a518(0xd8,0);
  FUN_8000a518(0xd9,0);
  FUN_8000a518(8,0);
  FUN_8000a518(0xb,0);
  FUN_800200e8(0xefa,0);
  uVar2 = FUN_8001ffb4(0xc91);
  uVar1 = countLeadingZeros(uVar2);
  FUN_800200e8(0xcbb,uVar1 >> 5);
  return;
}

