// Function: FUN_8027efc0
// Entry: 8027efc0
// Size: 96 bytes

void FUN_8027efc0(int param_1)

{
  if (*(char *)(param_1 + 0xec) == '\0') {
    return;
  }
  if (*(int *)(param_1 + 0x10) == 0) {
    (&DAT_803cc228)[(uint)*(byte *)(param_1 + 0xef) * 0x2f] = *(undefined4 *)(param_1 + 0xc);
  }
  else {
    *(undefined4 *)(*(int *)(param_1 + 0x10) + 0xc) = *(undefined4 *)(param_1 + 0xc);
  }
  if (*(int *)(param_1 + 0xc) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0xc) + 0x10) = *(undefined4 *)(param_1 + 0x10);
  }
  *(undefined *)(param_1 + 0xec) = 0;
  return;
}

