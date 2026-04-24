// Function: FUN_8025b4c4
// Entry: 8025b4c4
// Size: 204 bytes

void FUN_8025b4c4(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  iVar1 = param_2 * 4;
  uVar2 = *(uint *)(DAT_803dd210 + param_1 * 4 + 0x45c);
  *(uint *)(DAT_803dd210 + iVar1 + 0xb8) =
       uVar2 & 0x3ff | *(uint *)(DAT_803dd210 + iVar1 + 0xb8) & 0xffff0000;
  *(uint *)(DAT_803dd210 + iVar1 + 0xd8) =
       uVar2 >> 10 & 0x3ff | *(uint *)(DAT_803dd210 + iVar1 + 0xd8) & 0xffff0000;
  uVar3 = *(uint *)(DAT_803dd210 + param_1 * 4 + 0x47c);
  uVar2 = countLeadingZeros(1 - (uVar3 & 3));
  *(uint *)(DAT_803dd210 + iVar1 + 0xb8) =
       *(uint *)(DAT_803dd210 + iVar1 + 0xb8) & 0xfffeffff | (uVar2 & 0x1fe0) << 0xb;
  uVar2 = countLeadingZeros(1 - (uVar3 >> 2 & 3));
  *(uint *)(DAT_803dd210 + iVar1 + 0xd8) =
       *(uint *)(DAT_803dd210 + iVar1 + 0xd8) & 0xfffeffff | (uVar2 & 0x1fe0) << 0xb;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + iVar1 + 0xb8);
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + iVar1 + 0xd8);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

