// Function: FUN_801bf37c
// Entry: 801bf37c
// Size: 104 bytes

void FUN_801bf37c(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e4cf0);
    iVar1 = *(int *)(*(int *)(iVar1 + 0x40c) + 0x18);
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_800604b4();
    }
  }
  return;
}

