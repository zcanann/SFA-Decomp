// Function: FUN_8024d868
// Entry: 8024d868
// Size: 152 bytes

uint FUN_8024d868(void)

{
  bool bVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  iVar4 = DAT_803ddfa0;
  FUN_8024377c();
  uVar2 = read_volatile_2(DAT_cc00202c);
  uVar6 = uVar2 & 0x7ff;
  do {
    uVar2 = read_volatile_2(DAT_cc00202c);
    uVar3 = read_volatile_2(DAT_cc00202e);
    uVar5 = uVar2 & 0x7ff;
    bVar1 = uVar6 != uVar5;
    uVar6 = uVar5;
  } while (bVar1);
  uVar6 = (uVar5 - 1) * 2 + ((uVar3 & 0x7ff) - 1) / (uint)*(ushort *)(DAT_803ddfa0 + 0x1a);
  FUN_802437a4();
  if (*(ushort *)(iVar4 + 0x18) <= uVar6) {
    uVar6 = uVar6 - *(ushort *)(iVar4 + 0x18);
  }
  return uVar6 >> 1;
}

