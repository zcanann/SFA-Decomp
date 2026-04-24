// Function: FUN_80208cac
// Entry: 80208cac
// Size: 80 bytes

void FUN_80208cac(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (((*(char *)(iVar1 + 0x6b) == '\0') && (*(char *)(iVar1 + 0x6a) != '\0')) &&
     (*(char *)(iVar1 + 0x69) != '\x04')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

