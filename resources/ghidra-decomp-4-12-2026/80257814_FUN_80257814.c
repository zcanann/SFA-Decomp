// Function: FUN_80257814
// Entry: 80257814
// Size: 292 bytes

void FUN_80257814(void)

{
  uint uVar1;
  short sVar2;
  uint uVar3;
  
  if (*(short *)(DAT_803dd210 + 4) == 0) {
    return;
  }
  uVar3 = *(uint *)(DAT_803dd210 + 0x14);
  uVar1 = *(uint *)(DAT_803dd210 + 0x18);
  if ((*(uint *)(DAT_803dd210 + 0x1c) >> 9 & 1) == 1) {
    sVar2 = 3;
  }
  else {
    sVar2 = 1;
  }
  *(ushort *)(DAT_803dd210 + 6) =
       ((ushort)uVar3 & 1) + ((ushort)(uVar3 >> 1) & 1) + ((ushort)(uVar3 >> 2) & 1) +
       ((ushort)(uVar3 >> 3) & 1) + ((ushort)(uVar3 >> 4) & 1) + ((ushort)(uVar3 >> 5) & 1) +
       ((ushort)(uVar3 >> 6) & 1) + ((ushort)(uVar3 >> 7) & 1) + ((ushort)(uVar3 >> 8) & 1) +
       (ushort)(byte)(&DAT_803dd220)[uVar3 >> 9 & 3] +
       (ushort)(byte)(&DAT_803dd220)[uVar3 >> 0xb & 3] * sVar2 +
       (ushort)(byte)(&DAT_803dd218)[uVar3 >> 0xd & 3] +
       (ushort)(byte)(&DAT_803dd218)[uVar3 >> 0xf & 3] + (ushort)(byte)(&DAT_803dd21c)[uVar1 & 3] +
       (ushort)(byte)(&DAT_803dd21c)[uVar1 >> 2 & 3] + (ushort)(byte)(&DAT_803dd21c)[uVar1 >> 4 & 3]
       + (ushort)(byte)(&DAT_803dd21c)[uVar1 >> 6 & 3] +
       (ushort)(byte)(&DAT_803dd21c)[uVar1 >> 8 & 3] +
       (ushort)(byte)(&DAT_803dd21c)[uVar1 >> 10 & 3] +
       (ushort)(byte)(&DAT_803dd21c)[uVar1 >> 0xc & 3] +
       (ushort)(byte)(&DAT_803dd21c)[uVar1 >> 0xe & 3];
  return;
}

