// Function: FUN_8019819c
// Entry: 8019819c
// Size: 172 bytes

void FUN_8019819c(int param_1)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  bVar1 = *(byte *)(*(int *)(param_1 + 0xb8) + 4);
  if ((bVar1 & 1) != 0) {
    *(byte *)(*(int *)(param_1 + 0xb8) + 4) = bVar1 & 0xfe;
    if (*(char *)(iVar2 + 0x1d) == '\x01') {
      if (*(short *)(iVar2 + 0x1a) != 0) {
        FUN_8000db90();
      }
      if (*(short *)(iVar2 + 0x22) != 0) {
        FUN_8000db90(param_1);
      }
    }
    else {
      if (*(short *)(iVar2 + 0x1a) != 0) {
        FUN_8000b824();
      }
      if (*(short *)(iVar2 + 0x22) != 0) {
        FUN_8000b824(param_1);
      }
    }
  }
  return;
}

