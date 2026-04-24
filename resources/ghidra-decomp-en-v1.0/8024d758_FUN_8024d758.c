// Function: FUN_8024d758
// Entry: 8024d758
// Size: 104 bytes

undefined4 FUN_8024d758(void)

{
  bool bVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar2 = read_volatile_2(DAT_cc00202c);
  uVar4 = uVar2 & 0x7ff;
  do {
    uVar2 = read_volatile_2(DAT_cc00202c);
    uVar3 = read_volatile_2(DAT_cc00202e);
    uVar5 = uVar2 & 0x7ff;
    bVar1 = uVar4 != uVar5;
    uVar4 = uVar5;
  } while (bVar1);
  if ((uVar5 - 1) * 2 + ((uVar3 & 0x7ff) - 1) / (uint)*(ushort *)(DAT_803ddfa0 + 0x1a) <
      (uint)*(ushort *)(DAT_803ddfa0 + 0x18)) {
    return 1;
  }
  return 0;
}

