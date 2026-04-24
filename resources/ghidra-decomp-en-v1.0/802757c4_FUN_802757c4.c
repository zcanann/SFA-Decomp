// Function: FUN_802757c4
// Entry: 802757c4
// Size: 408 bytes

void FUN_802757c4(int param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  uVar1 = (uint)*(byte *)(param_1 + 0x12f) + (int)(char)(*param_2 >> 8);
  if ((int)uVar1 < 0) {
    uVar1 = 0;
  }
  else if (0x7f < (int)uVar1) {
    uVar1 = 0x7f;
  }
  if (*(char *)(param_1 + 0x11d) != '\0') {
    uVar1 = uVar1 | 0x80;
  }
  *(undefined *)(param_1 + 0x11c) = 1;
  uVar3 = param_2[1];
  uVar2 = countLeadingZeros(-(uint)*(byte *)(param_1 + 0x193));
  uVar1 = FUN_80278b94(*param_2 >> 0x10,uVar3 >> 0x10 & 0xff,uVar3 >> 0x18,
                       *(undefined2 *)(param_1 + 0x100),uVar1 & 0xff,
                       *(uint *)(param_1 + 0x154) >> 0x10 & 0xff,
                       *(uint *)(param_1 + 0x170) >> 0x10 & 0xff,*(undefined *)(param_1 + 0x121),
                       *(undefined *)(param_1 + 0x122),*(undefined *)(param_1 + 0x123),
                       uVar3 & 0xffff,*(undefined *)(param_1 + 0x120),0,
                       *(undefined *)(param_1 + 0x11e),*(undefined *)(param_1 + 0x11f),uVar2 >> 5);
  *(undefined *)(param_1 + 0x11c) = 0;
  if (uVar1 == 0xffffffff) {
    *(undefined4 *)(param_1 + 0x108) = 0xffffffff;
  }
  else {
    iVar4 = (uVar1 & 0xff) * 0x404;
    *(undefined4 *)(param_1 + 0x108) = *(undefined4 *)(*(int *)(DAT_803de268 + iVar4 + 0xf8) + 8);
    *(undefined4 *)(DAT_803de268 + iVar4 + 0xf0) = *(undefined4 *)(param_1 + 0xf4);
    if (*(int *)(param_1 + 0xec) != -1) {
      *(int *)(DAT_803de268 + iVar4 + 0xec) = *(int *)(param_1 + 0xec);
      *(uint *)(DAT_803de268 + (*(uint *)(param_1 + 0xec) & 0xff) * 0x404 + 0xf0) = uVar1;
    }
    *(uint *)(param_1 + 0xec) = uVar1;
    if (*(char *)(param_1 + 0x11d) != '\0') {
      FUN_80271a3c(DAT_803de268 + iVar4,param_1);
    }
  }
  return;
}

