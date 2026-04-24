// Function: FUN_80265080
// Entry: 80265080
// Size: 444 bytes

void FUN_80265080(uint param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = DAT_803de210 + (param_1 & 0xff) * 0xe0 + 0x300;
  iVar5 = 4;
  iVar3 = 0;
  iVar4 = 1;
  iVar1 = iVar2;
  do {
    if (*(char *)(DAT_803de1a4 + iVar4 + -1) == '\0') {
      *(undefined4 *)(iVar1 + 0x48) = 0xffffffff;
      *(undefined4 *)(iVar1 + 0x90) = 0xffffffff;
    }
    else {
      *(uint *)(iVar1 + 0x90) = iVar3 - (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2);
      iVar3 = iVar3 + (uint)*(byte *)(DAT_803de1a4 + iVar4 + -1);
      *(uint *)(iVar1 + 0x48) = (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2 + -2);
    }
    if (*(char *)(DAT_803de1a4 + iVar4) == '\0') {
      *(undefined4 *)(iVar1 + 0x4c) = 0xffffffff;
      *(undefined4 *)(iVar1 + 0x94) = 0xffffffff;
    }
    else {
      *(uint *)(iVar1 + 0x94) = iVar3 - (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2);
      iVar3 = iVar3 + (uint)*(byte *)(DAT_803de1a4 + iVar4);
      *(uint *)(iVar1 + 0x4c) = (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2 + -2);
    }
    if (*(char *)(DAT_803de1a4 + iVar4 + 1) == '\0') {
      *(undefined4 *)(iVar1 + 0x50) = 0xffffffff;
      *(undefined4 *)(iVar1 + 0x98) = 0xffffffff;
    }
    else {
      *(uint *)(iVar1 + 0x98) = iVar3 - (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2);
      iVar3 = iVar3 + (uint)*(byte *)(DAT_803de1a4 + iVar4 + 1);
      *(uint *)(iVar1 + 0x50) = (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2 + -2);
    }
    if (*(char *)(DAT_803de1a4 + iVar4 + 2) == '\0') {
      *(undefined4 *)(iVar1 + 0x54) = 0xffffffff;
      *(undefined4 *)(iVar1 + 0x9c) = 0xffffffff;
    }
    else {
      *(uint *)(iVar1 + 0x9c) = iVar3 - (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2);
      iVar3 = iVar3 + (uint)*(byte *)(DAT_803de1a4 + iVar4 + 2);
      *(uint *)(iVar1 + 0x54) = (uint)*(ushort *)(DAT_803de1ac + iVar3 * 2 + -2);
    }
    iVar4 = iVar4 + 4;
    iVar5 = iVar5 + -1;
    iVar1 = iVar1 + 0x10;
  } while (iVar5 != 0);
  *(undefined4 *)(iVar2 + 0x88) = 0xfffff;
  return;
}

