// Function: FUN_8027ef1c
// Entry: 8027ef1c
// Size: 164 bytes

void FUN_8027ef1c(int param_1,byte param_2)

{
  int iVar1;
  
  if (*(char *)(param_1 + 0xec) != '\0') {
    FUN_8027efc0(param_1);
    *(uint *)(param_1 + 0x24) = *(uint *)(param_1 + 0x24) | 0x20;
  }
  *(undefined *)(param_1 + 0xed) = 0;
  iVar1 = (&DAT_803cc228)[(uint)param_2 * 0x2f];
  *(int *)(param_1 + 0xc) = iVar1;
  if (iVar1 != 0) {
    *(int *)(*(int *)(param_1 + 0xc) + 0x10) = param_1;
  }
  *(undefined4 *)(param_1 + 0x10) = 0;
  (&DAT_803cc228)[(uint)param_2 * 0x2f] = param_1;
  *(undefined *)(param_1 + 0xee) = 0;
  *(undefined *)(param_1 + 0xec) = 1;
  *(byte *)(param_1 + 0xef) = param_2;
  return;
}

