// Function: FUN_80088f20
// Entry: 80088f20
// Size: 372 bytes

void FUN_80088f20(uint param_1,char param_2)

{
  undefined4 *puVar1;
  int iVar2;
  
  if ((param_1 & 1) != 0) {
    if (param_2 == '\0') {
      *(byte *)(DAT_803dddac + 0xc1) = *(byte *)(DAT_803dddac + 0xc1) & 0x7f;
    }
    else {
      *(byte *)(DAT_803dddac + 0xc1) = *(byte *)(DAT_803dddac + 0xc1) & 0x7f | 0x80;
    }
  }
  if ((param_1 & 2) != 0) {
    if (param_2 == '\0') {
      *(byte *)(DAT_803dddac + 0x165) = *(byte *)(DAT_803dddac + 0x165) & 0x7f;
    }
    else {
      *(byte *)(DAT_803dddac + 0x165) = *(byte *)(DAT_803dddac + 0x165) & 0x7f | 0x80;
    }
  }
  *(byte *)(DAT_803dddac + 0x209) =
       *(byte *)(DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x24c) * 0xa4 + 0xc1) & 0x80 |
       *(byte *)(DAT_803dddac + 0x209) & 0x7f;
  puVar1 = FUN_800e877c();
  iVar2 = FUN_800e8a48();
  if (iVar2 == 0) {
    if (*(char *)(DAT_803dddac + 0xc1) < '\0') {
      *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 2;
    }
    else {
      *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xfd;
    }
    if (*(char *)(DAT_803dddac + 0x165) < '\0') {
      *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 4;
    }
    else {
      *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xfb;
    }
  }
  return;
}

