// Function: FUN_80036ae8
// Entry: 80036ae8
// Size: 268 bytes

void FUN_80036ae8(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  iVar1 = 0;
  iVar3 = 3;
  do {
    *(undefined4 *)(DAT_803dd85c + iVar1) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x3c) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x78) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0xb4) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0xf0) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 300) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x168) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x1a4) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x1e0) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x21c) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 600) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x294) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x2d0) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x30c) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x348) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 900) = 0;
    iVar1 = iVar1 + 0x3c0;
    iVar2 = iVar2 + 0x10;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  iVar3 = iVar2 * 0x3c;
  iVar1 = 0x32 - iVar2;
  if (iVar2 < 0x32) {
    do {
      *(undefined4 *)(DAT_803dd85c + iVar3) = 0;
      iVar3 = iVar3 + 0x3c;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  DAT_803dd860 = 0;
  return;
}

