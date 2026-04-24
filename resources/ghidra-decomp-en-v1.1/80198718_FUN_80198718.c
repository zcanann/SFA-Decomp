// Function: FUN_80198718
// Entry: 80198718
// Size: 172 bytes

void FUN_80198718(int param_1)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  bVar1 = *(byte *)(*(int *)(param_1 + 0xb8) + 4);
  if ((bVar1 & 1) != 0) {
    *(byte *)(*(int *)(param_1 + 0xb8) + 4) = bVar1 & 0xfe;
    if (*(char *)(iVar2 + 0x1d) == '\x01') {
      if (*(short *)(iVar2 + 0x1a) != 0) {
        FUN_8000dbb0();
      }
      if (*(short *)(iVar2 + 0x22) != 0) {
        FUN_8000dbb0();
      }
    }
    else {
      if (*(short *)(iVar2 + 0x1a) != 0) {
        FUN_8000b844(param_1,*(short *)(iVar2 + 0x1a));
      }
      if (*(short *)(iVar2 + 0x22) != 0) {
        FUN_8000b844(param_1,*(short *)(iVar2 + 0x22));
      }
    }
  }
  return;
}

