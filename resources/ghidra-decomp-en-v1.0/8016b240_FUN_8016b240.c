// Function: FUN_8016b240
// Entry: 8016b240
// Size: 108 bytes

void FUN_8016b240(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if ((*piVar1 != 0) && (param_2 == 0)) {
    FUN_8002cbc4();
    *piVar1 = 0;
  }
  (**(code **)(*DAT_803dca7c + 0x18))(param_1);
  return;
}

