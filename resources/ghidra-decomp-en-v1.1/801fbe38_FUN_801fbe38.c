// Function: FUN_801fbe38
// Entry: 801fbe38
// Size: 104 bytes

void FUN_801fbe38(uint param_1)

{
  short sVar1;
  
  FUN_8002bac4();
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x3b7) {
    FUN_801fba6c();
  }
  else if (sVar1 == 0x3bf) {
    FUN_801fb874(param_1);
  }
  else if (sVar1 == 0x53f) {
    FUN_801fb874(param_1);
  }
  return;
}

