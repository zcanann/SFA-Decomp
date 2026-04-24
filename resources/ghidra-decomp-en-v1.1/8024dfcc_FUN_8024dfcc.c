// Function: FUN_8024dfcc
// Entry: 8024dfcc
// Size: 152 bytes

uint FUN_8024dfcc(void)

{
  bool bVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  iVar4 = DAT_803dec20;
  FUN_80243e74();
  uVar2 = DAT_cc00202c;
  uVar6 = uVar2 & 0x7ff;
  do {
    uVar2 = DAT_cc00202c;
    uVar3 = DAT_cc00202e;
    uVar5 = uVar2 & 0x7ff;
    bVar1 = uVar6 != uVar5;
    uVar6 = uVar5;
  } while (bVar1);
  uVar6 = (uVar5 - 1) * 2 + ((uVar3 & 0x7ff) - 1) / (uint)*(ushort *)(DAT_803dec20 + 0x1a);
  FUN_80243e9c();
  if (*(ushort *)(iVar4 + 0x18) <= uVar6) {
    uVar6 = uVar6 - *(ushort *)(iVar4 + 0x18);
  }
  return uVar6 >> 1;
}

