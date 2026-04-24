// Function: FUN_8012fdd4
// Entry: 8012fdd4
// Size: 248 bytes

void FUN_8012fdd4(void)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  short *psVar5;
  
  DAT_803dd896 = 0xff;
  DAT_803dd894 = 0xffff;
  DAT_803dd8c2 = 0xffff;
  DAT_803dd8b8 = 0;
  DAT_803dd830 = 0xffff;
  uVar1 = FUN_8006fed4();
  DAT_803dd744 = (uVar1 & 0xffff) - 0x140;
  DAT_803dd740 = ((int)uVar1 >> 0x10) + -0xf0;
  iVar3 = 0;
  psVar5 = &DAT_8031b624;
  puVar4 = &DAT_803a89b0;
  do {
    uVar2 = FUN_80054d54((int)*psVar5);
    *puVar4 = uVar2;
    psVar5 = psVar5 + 1;
    puVar4 = puVar4 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x66);
  DAT_803dd8c4 = FUN_80054d54(0x500);
  *(undefined2 *)(DAT_803dd8c4 + 0x14) = 0x28;
  DAT_803a9398 = 0;
  DAT_803a939c = 0xffffffff;
  DAT_803a93a0 = FLOAT_803e1e3c;
  DAT_803a93a4 = 0;
  DAT_803dd7d0 = 0;
  DAT_803dd828 = 0;
  DAT_803dd82c = 0x80000;
  DAT_803dd884 = 0;
  return;
}

