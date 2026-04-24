// Function: FUN_80088c94
// Entry: 80088c94
// Size: 372 bytes

void FUN_80088c94(uint param_1,char param_2)

{
  int iVar1;
  int iVar2;
  
  if ((param_1 & 1) != 0) {
    if (param_2 == '\0') {
      *(byte *)(DAT_803dd12c + 0xc1) = *(byte *)(DAT_803dd12c + 0xc1) & 0x7f;
    }
    else {
      *(byte *)(DAT_803dd12c + 0xc1) = *(byte *)(DAT_803dd12c + 0xc1) & 0x7f | 0x80;
    }
  }
  if ((param_1 & 2) != 0) {
    if (param_2 == '\0') {
      *(byte *)(DAT_803dd12c + 0x165) = *(byte *)(DAT_803dd12c + 0x165) & 0x7f;
    }
    else {
      *(byte *)(DAT_803dd12c + 0x165) = *(byte *)(DAT_803dd12c + 0x165) & 0x7f | 0x80;
    }
  }
  *(byte *)(DAT_803dd12c + 0x209) =
       *(byte *)(DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x24c) * 0xa4 + 0xc1) & 0x80 |
       *(byte *)(DAT_803dd12c + 0x209) & 0x7f;
  iVar1 = FUN_800e84f8();
  iVar2 = FUN_800e87c4();
  if (iVar2 == 0) {
    if (*(char *)(DAT_803dd12c + 0xc1) < '\0') {
      *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) | 2;
    }
    else {
      *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) & 0xfd;
    }
    if (*(char *)(DAT_803dd12c + 0x165) < '\0') {
      *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) | 4;
    }
    else {
      *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) & 0xfb;
    }
  }
  return;
}

