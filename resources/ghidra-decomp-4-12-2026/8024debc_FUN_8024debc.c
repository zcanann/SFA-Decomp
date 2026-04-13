// Function: FUN_8024debc
// Entry: 8024debc
// Size: 104 bytes

undefined4 FUN_8024debc(void)

{
  bool bVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar2 = DAT_cc00202c;
  uVar4 = uVar2 & 0x7ff;
  do {
    uVar2 = DAT_cc00202c;
    uVar3 = DAT_cc00202e;
    uVar5 = uVar2 & 0x7ff;
    bVar1 = uVar4 != uVar5;
    uVar4 = uVar5;
  } while (bVar1);
  if ((uVar5 - 1) * 2 + ((uVar3 & 0x7ff) - 1) / (uint)*(ushort *)(DAT_803dec20 + 0x1a) <
      (uint)*(ushort *)(DAT_803dec20 + 0x18)) {
    return 1;
  }
  return 0;
}

