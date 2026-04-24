// Function: FUN_802570b0
// Entry: 802570b0
// Size: 292 bytes

void FUN_802570b0(void)

{
  uint uVar1;
  short sVar2;
  uint uVar3;
  
  if (*(short *)(DAT_803dc5a8 + 4) == 0) {
    return;
  }
  uVar3 = *(uint *)(DAT_803dc5a8 + 0x14);
  uVar1 = *(uint *)(DAT_803dc5a8 + 0x18);
  if ((*(uint *)(DAT_803dc5a8 + 0x1c) >> 9 & 1) == 1) {
    sVar2 = 3;
  }
  else {
    sVar2 = 1;
  }
  *(ushort *)(DAT_803dc5a8 + 6) =
       ((ushort)uVar3 & 1) + ((ushort)(uVar3 >> 1) & 1) + ((ushort)(uVar3 >> 2) & 1) +
       ((ushort)(uVar3 >> 3) & 1) + ((ushort)(uVar3 >> 4) & 1) + ((ushort)(uVar3 >> 5) & 1) +
       ((ushort)(uVar3 >> 6) & 1) + ((ushort)(uVar3 >> 7) & 1) + ((ushort)(uVar3 >> 8) & 1) +
       (ushort)(byte)(&DAT_803dc5b8)[uVar3 >> 9 & 3] +
       (ushort)(byte)(&DAT_803dc5b8)[uVar3 >> 0xb & 3] * sVar2 +
       (ushort)(byte)(&DAT_803dc5b0)[uVar3 >> 0xd & 3] +
       (ushort)(byte)(&DAT_803dc5b0)[uVar3 >> 0xf & 3] + (ushort)(byte)(&DAT_803dc5b4)[uVar1 & 3] +
       (ushort)(byte)(&DAT_803dc5b4)[uVar1 >> 2 & 3] + (ushort)(byte)(&DAT_803dc5b4)[uVar1 >> 4 & 3]
       + (ushort)(byte)(&DAT_803dc5b4)[uVar1 >> 6 & 3] +
       (ushort)(byte)(&DAT_803dc5b4)[uVar1 >> 8 & 3] +
       (ushort)(byte)(&DAT_803dc5b4)[uVar1 >> 10 & 3] +
       (ushort)(byte)(&DAT_803dc5b4)[uVar1 >> 0xc & 3] +
       (ushort)(byte)(&DAT_803dc5b4)[uVar1 >> 0xe & 3];
  return;
}

