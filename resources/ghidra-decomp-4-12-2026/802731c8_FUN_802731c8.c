// Function: FUN_802731c8
// Entry: 802731c8
// Size: 248 bytes

void FUN_802731c8(int param_1)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  uint *puVar4;
  int iVar5;
  uint uVar6;
  
  uVar6 = DAT_803deee4;
  if (param_1 == 1) {
    DAT_803deee4 = DAT_803deee4 & 0xfffffffc;
    FUN_802846b0();
  }
  else if (param_1 < 1) {
    if (-1 < param_1) {
      DAT_803deee4 = DAT_803deee4 & 0xfffffffd | 1;
      FUN_802846b0();
    }
  }
  else if (param_1 < 3) {
    DAT_803deee4 = DAT_803deee4 & 0xfffffffe | 2;
    FUN_802846b0();
  }
  if (uVar6 != DAT_803deee4) {
    iVar5 = 0;
    for (uVar6 = 0; uVar6 < DAT_803bdfc0; uVar6 = uVar6 + 1) {
      iVar2 = iVar5 + 0x114;
      iVar5 = iVar5 + 0x404;
      puVar4 = (uint *)(DAT_803deee8 + iVar2);
      uVar1 = *puVar4;
      puVar3 = (uint *)(DAT_803deee8 + iVar2);
      puVar3[1] = puVar4[1];
      *puVar3 = uVar1 | 0x2000;
    }
    FUN_80273fd4();
  }
  return;
}

