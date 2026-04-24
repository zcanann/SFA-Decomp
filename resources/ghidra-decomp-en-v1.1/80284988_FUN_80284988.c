// Function: FUN_80284988
// Entry: 80284988
// Size: 544 bytes

void FUN_80284988(int param_1)

{
  int iVar1;
  undefined2 *puVar2;
  undefined2 *puVar3;
  uint uVar4;
  int iVar5;
  
  iVar1 = FUN_802508f4();
  puVar2 = (undefined2 *)FUN_802852d0();
  iVar5 = 8;
  puVar3 = puVar2;
  do {
    *puVar3 = 0;
    puVar3[1] = 0;
    puVar3[2] = 0;
    puVar3[3] = 0;
    puVar3[4] = 0;
    puVar3[5] = 0;
    puVar3[6] = 0;
    puVar3[7] = 0;
    puVar3[8] = 0;
    puVar3[9] = 0;
    puVar3[10] = 0;
    puVar3[0xb] = 0;
    puVar3[0xc] = 0;
    puVar3[0xd] = 0;
    puVar3[0xe] = 0;
    puVar3[0xf] = 0;
    puVar3[0x10] = 0;
    puVar3[0x11] = 0;
    puVar3[0x12] = 0;
    puVar3[0x13] = 0;
    puVar3[0x14] = 0;
    puVar3[0x15] = 0;
    puVar3[0x16] = 0;
    puVar3[0x17] = 0;
    puVar3[0x18] = 0;
    puVar3[0x19] = 0;
    puVar3[0x1a] = 0;
    puVar3[0x1b] = 0;
    puVar3[0x1c] = 0;
    puVar3[0x1d] = 0;
    puVar3[0x1e] = 0;
    puVar3[0x1f] = 0;
    puVar3[0x20] = 0;
    puVar3[0x21] = 0;
    puVar3[0x22] = 0;
    puVar3[0x23] = 0;
    puVar3[0x24] = 0;
    puVar3[0x25] = 0;
    puVar3[0x26] = 0;
    puVar3[0x27] = 0;
    puVar3[0x28] = 0;
    puVar3[0x29] = 0;
    puVar3[0x2a] = 0;
    puVar3[0x2b] = 0;
    puVar3[0x2c] = 0;
    puVar3[0x2d] = 0;
    puVar3[0x2e] = 0;
    puVar3[0x2f] = 0;
    puVar3[0x30] = 0;
    puVar3[0x31] = 0;
    puVar3[0x32] = 0;
    puVar3[0x33] = 0;
    puVar3[0x34] = 0;
    puVar3[0x35] = 0;
    puVar3[0x36] = 0;
    puVar3[0x37] = 0;
    puVar3[0x38] = 0;
    puVar3[0x39] = 0;
    puVar3[0x3a] = 0;
    puVar3[0x3b] = 0;
    puVar3[0x3c] = 0;
    puVar3[0x3d] = 0;
    puVar3[0x3e] = 0;
    puVar3[0x3f] = 0;
    puVar3[0x40] = 0;
    puVar3[0x41] = 0;
    puVar3[0x42] = 0;
    puVar3[0x43] = 0;
    puVar3[0x44] = 0;
    puVar3[0x45] = 0;
    puVar3[0x46] = 0;
    puVar3[0x47] = 0;
    puVar3[0x48] = 0;
    puVar3[0x49] = 0;
    puVar3[0x4a] = 0;
    puVar3[0x4b] = 0;
    puVar3[0x4c] = 0;
    puVar3[0x4d] = 0;
    puVar3[0x4e] = 0;
    puVar3[0x4f] = 0;
    puVar3 = puVar3 + 0x50;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  FUN_802420e0((uint)puVar2,0x500);
  DAT_803d4e41 = '\0';
  DAT_803d4e40 = 0;
  DAT_803d50c5 = 0;
  DAT_803d50c4 = 0;
  FUN_8028479c(puVar2,iVar1,0x500,0,0,0);
  do {
  } while (DAT_803d4e41 != '\0');
  FUN_802852f8();
  DAT_803df000 = iVar1 + param_1;
  uVar4 = FUN_802508fc();
  if (uVar4 < DAT_803df000) {
    DAT_803df000 = FUN_802508fc();
  }
  DAT_803df004 = iVar1 + 0x500;
  DAT_803df00c = 0;
  FUN_80284cd4();
  return;
}

