// Function: FUN_802967e0
// Entry: 802967e0
// Size: 188 bytes

void FUN_802967e0(int param_1,int param_2)

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
    *(undefined *)(iVar1 + 0x8b4) = 2;
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
    *(undefined *)(iVar1 + 0x8b4) = 4;
    *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xf7;
    return;
  }
  if (DAT_803de44c == 0) {
    return;
  }
  if ((*(byte *)(iVar1 + 0x3f4) >> 6 & 1) == 0) {
    return;
  }
  *(undefined *)(iVar1 + 0x8b4) = 4;
  *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xf7 | 8;
  return;
}

