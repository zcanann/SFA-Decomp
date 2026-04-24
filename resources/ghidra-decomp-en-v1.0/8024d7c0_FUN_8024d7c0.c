// Function: FUN_8024d7c0
// Entry: 8024d7c0
// Size: 168 bytes

ushort FUN_8024d7c0(void)

{
  bool bVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  
  FUN_8024377c();
  uVar2 = read_volatile_2(DAT_cc00202c);
  uVar5 = uVar2 & 0x7ff;
  do {
    uVar2 = read_volatile_2(DAT_cc00202c);
    uVar4 = read_volatile_2(DAT_cc00202e);
    uVar6 = uVar2 & 0x7ff;
    bVar1 = uVar5 != uVar6;
    uVar5 = uVar6;
  } while (bVar1);
  uVar2 = *(ushort *)(DAT_803ddfa0 + 0x1a);
  uVar3 = *(ushort *)(DAT_803ddfa0 + 0x18);
  FUN_802437a4();
  return (uVar6 - 1) * 2 + ((uVar4 & 0x7ff) - 1) / (uint)uVar2 < (uint)uVar3 ^ 1 ^ DAT_803ae162 & 1;
}

