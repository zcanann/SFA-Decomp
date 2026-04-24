// Function: FUN_801b07c0
// Entry: 801b07c0
// Size: 136 bytes

void FUN_801b07c0(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x18))();
  if ((piVar1[1] != 0) && (param_2 == 0)) {
    FUN_8002cbc4();
  }
  FUN_80036fa4(param_1,0x31);
  if (*piVar1 != 0) {
    FUN_8001f384();
  }
  return;
}

