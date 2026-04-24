// Function: FUN_801bfbc4
// Entry: 801bfbc4
// Size: 100 bytes

void FUN_801bfbc4(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e4d44);
    iVar1 = *(int *)(iVar1 + 4);
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_800604b4();
    }
  }
  return;
}

