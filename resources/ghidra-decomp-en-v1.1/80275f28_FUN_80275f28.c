// Function: FUN_80275f28
// Entry: 80275f28
// Size: 408 bytes

void FUN_80275f28(int param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  
  iVar1 = (uint)*(byte *)(param_1 + 0x12f) + (int)(char)(*param_2 >> 8);
  if (iVar1 < 0) {
    iVar1 = 0;
  }
  else if (0x7f < iVar1) {
    iVar1 = 0x7f;
  }
  bVar3 = (byte)iVar1;
  if (*(char *)(param_1 + 0x11d) != '\0') {
    bVar3 = bVar3 | 0x80;
  }
  *(undefined *)(param_1 + 0x11c) = 1;
  uVar4 = param_2[1];
  uVar2 = countLeadingZeros(-(uint)*(byte *)(param_1 + 0x193));
  uVar2 = FUN_802792f8(*param_2 >> 0x10,(byte)(uVar4 >> 0x10),(byte)(uVar4 >> 0x18),
                       *(short *)(param_1 + 0x100),bVar3,
                       (char)((uint)*(undefined4 *)(param_1 + 0x154) >> 0x10),
                       (char)((uint)*(undefined4 *)(param_1 + 0x170) >> 0x10),
                       (uint)*(byte *)(param_1 + 0x121),*(byte *)(param_1 + 0x122),
                       *(undefined *)(param_1 + 0x123),(ushort)uVar4,*(undefined *)(param_1 + 0x120)
                       ,0,*(undefined *)(param_1 + 0x11e),*(undefined *)(param_1 + 0x11f),uVar2 >> 5
                      );
  *(undefined *)(param_1 + 0x11c) = 0;
  if (uVar2 == 0xffffffff) {
    *(undefined4 *)(param_1 + 0x108) = 0xffffffff;
  }
  else {
    iVar1 = (uVar2 & 0xff) * 0x404;
    *(undefined4 *)(param_1 + 0x108) = *(undefined4 *)(*(int *)(DAT_803deee8 + iVar1 + 0xf8) + 8);
    *(undefined4 *)(DAT_803deee8 + iVar1 + 0xf0) = *(undefined4 *)(param_1 + 0xf4);
    if (*(int *)(param_1 + 0xec) != -1) {
      *(int *)(DAT_803deee8 + iVar1 + 0xec) = *(int *)(param_1 + 0xec);
      *(uint *)(DAT_803deee8 + (*(uint *)(param_1 + 0xec) & 0xff) * 0x404 + 0xf0) = uVar2;
    }
    *(uint *)(param_1 + 0xec) = uVar2;
    if (*(char *)(param_1 + 0x11d) != '\0') {
      FUN_802721a0(DAT_803deee8 + iVar1,param_1);
    }
  }
  return;
}

