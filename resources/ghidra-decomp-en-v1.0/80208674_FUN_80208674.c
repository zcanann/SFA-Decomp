// Function: FUN_80208674
// Entry: 80208674
// Size: 80 bytes

void FUN_80208674(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (((*(char *)(iVar1 + 0x6b) == '\0') && (*(char *)(iVar1 + 0x6a) != '\0')) &&
     (*(char *)(iVar1 + 0x69) != '\x04')) {
    FUN_8003b8f4((double)FLOAT_803e6490);
  }
  return;
}

