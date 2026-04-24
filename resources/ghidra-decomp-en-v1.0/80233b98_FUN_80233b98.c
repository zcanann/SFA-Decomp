// Function: FUN_80233b98
// Entry: 80233b98
// Size: 72 bytes

void FUN_80233b98(int param_1)

{
  int iVar1;
  
  iVar1 = **(int **)(param_1 + 0xb8);
  if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
    FUN_800604b4();
  }
  return;
}

