// Function: FUN_801bd364
// Entry: 801bd364
// Size: 176 bytes

void FUN_801bd364(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) && (*(short *)(iVar1 + 0x402) != 3)) {
    FUN_8003b8f4((double)FLOAT_803e4c44);
    FUN_801bb598(param_1,iVar1);
    FUN_80114dec(param_1,&DAT_803ac9dc,0);
    iVar1 = **(int **)(iVar1 + 0x40c);
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_800604b4();
    }
  }
  return;
}

