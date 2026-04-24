// Function: FUN_8018cf40
// Entry: 8018cf40
// Size: 100 bytes

void FUN_8018cf40(int param_1)

{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e3d78);
    iVar1 = *piVar2;
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_800604b4();
    }
  }
  return;
}

