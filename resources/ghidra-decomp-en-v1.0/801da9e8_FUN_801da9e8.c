// Function: FUN_801da9e8
// Entry: 801da9e8
// Size: 112 bytes

void FUN_801da9e8(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x18))();
  if (((param_2 == 0) && (*piVar1 != 0)) && ((*(ushort *)(*piVar1 + 0xb0) & 0x40) == 0)) {
    FUN_8002cbc4();
  }
  return;
}

