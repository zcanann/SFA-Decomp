// Function: FUN_80256f84
// Entry: 80256f84
// Size: 344 bytes

void FUN_80256f84(void)

{
  int iVar1;
  uint uVar2;
  
  if (*(char *)(DAT_803dd210 + 0x41d) == '\0') {
    if (*(char *)(DAT_803dd210 + 0x41c) == '\0') {
      iVar1 = 0;
    }
    else {
      iVar1 = 1;
    }
  }
  else {
    iVar1 = 2;
  }
  uVar2 = *(uint *)(DAT_803dd210 + 0x18);
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = 0x1008;
  DAT_cc008000 = ((uint)((uVar2 & 3) != 0) + (uint)((uVar2 >> 2 & 3) != 0) +
                  (uint)((uVar2 >> 4 & 3) != 0) + (uint)((uVar2 >> 6 & 3) != 0) +
                  (uint)((uVar2 >> 8 & 3) != 0) + (uint)((uVar2 >> 10 & 3) != 0) +
                  (uint)((uVar2 >> 0xc & 3) != 0) + (uint)((uVar2 >> 0xe & 3) != 0)) * 0x10 |
                 (uint)((*(uint *)(DAT_803dd210 + 0x14) >> 0xd & 3) != 0) +
                 (uint)((*(uint *)(DAT_803dd210 + 0x14) >> 0xf & 3) != 0) | iVar1 << 2;
  *(undefined2 *)(DAT_803dd210 + 2) = 1;
  return;
}

