// Function: FUN_8024df24
// Entry: 8024df24
// Size: 168 bytes

ushort FUN_8024df24(void)

{
  bool bVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  
  FUN_80243e74();
  uVar2 = DAT_cc00202c;
  uVar5 = uVar2 & 0x7ff;
  do {
    uVar2 = DAT_cc00202c;
    uVar4 = DAT_cc00202e;
    uVar6 = uVar2 & 0x7ff;
    bVar1 = uVar5 != uVar6;
    uVar5 = uVar6;
  } while (bVar1);
  uVar2 = *(ushort *)(DAT_803dec20 + 0x1a);
  uVar3 = *(ushort *)(DAT_803dec20 + 0x18);
  FUN_80243e9c();
  return (uVar6 - 1) * 2 + ((uVar4 & 0x7ff) - 1) / (uint)uVar2 < (uint)uVar3 ^ 1 ^ DAT_803aedc2 & 1;
}

