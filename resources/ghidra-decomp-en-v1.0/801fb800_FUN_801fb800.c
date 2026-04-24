// Function: FUN_801fb800
// Entry: 801fb800
// Size: 104 bytes

void FUN_801fb800(int param_1)

{
  short sVar1;
  
  FUN_8002b9ec();
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x3b7) {
    FUN_801fb434(param_1);
  }
  else if (sVar1 == 0x3bf) {
    FUN_801fb23c(param_1);
  }
  else if (sVar1 == 0x53f) {
    FUN_801fb23c(param_1);
  }
  return;
}

