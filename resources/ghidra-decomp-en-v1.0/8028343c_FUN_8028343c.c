// Function: FUN_8028343c
// Entry: 8028343c
// Size: 80 bytes

void FUN_8028343c(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803de344 + param_1 * 0xf4;
  if ((*(char *)(iVar1 + 0xec) == '\x01') && (DAT_803de370 == 0)) {
    *(undefined *)(iVar1 + 0xee) = 1;
  }
  iVar1 = DAT_803de344 + param_1 * 0xf4 + (uint)DAT_803de370 * 4;
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 0x20;
  return;
}

