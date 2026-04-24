// Function: FUN_80186aec
// Entry: 80186aec
// Size: 168 bytes

void FUN_80186aec(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_8001f384();
    *piVar1 = 0;
  }
  if (((param_2 == 0) && (*piVar1 != 0)) && (*(byte *)(piVar1 + 0x1c) >> 6 != 1)) {
    DAT_803ddad8 = 0;
  }
  FUN_80036fa4(param_1,0x30);
  (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  return;
}

