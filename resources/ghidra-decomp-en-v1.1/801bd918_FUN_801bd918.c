// Function: FUN_801bd918
// Entry: 801bd918
// Size: 176 bytes

void FUN_801bd918(short *param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (((in_r8 != '\0') && (*(int *)(param_1 + 0x7a) == 0)) && (*(short *)(iVar1 + 0x402) != 3)) {
    FUN_8003b9ec((int)param_1);
    FUN_801bbb4c();
    FUN_80115088(param_1,-0x7fc529c4,0);
    iVar1 = **(int **)(iVar1 + 0x40c);
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_80060630(iVar1);
    }
  }
  return;
}

