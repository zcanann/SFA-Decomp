// Function: FUN_8029672c
// Entry: 8029672c
// Size: 180 bytes

void FUN_8029672c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0) {
    if (DAT_803de44c == 0) {
      return;
    }
    if ((*(byte *)(iVar1 + 0x3f4) >> 6 & 1) == 0) {
      return;
    }
    *(undefined *)(iVar1 + 0x8b4) = 0;
    *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xf7;
    return;
  }
  if (param_2 != 1) {
    if (DAT_803de44c == 0) {
      return;
    }
    if ((*(byte *)(iVar1 + 0x3f4) >> 6 & 1) == 0) {
      return;
    }
    *(undefined *)(iVar1 + 0x8b4) = 1;
    *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xf7;
    return;
  }
  if (DAT_803de44c == 0) {
    return;
  }
  if ((*(byte *)(iVar1 + 0x3f4) >> 6 & 1) == 0) {
    return;
  }
  *(undefined *)(iVar1 + 0x8b4) = 1;
  *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xf7 | 8;
  return;
}

