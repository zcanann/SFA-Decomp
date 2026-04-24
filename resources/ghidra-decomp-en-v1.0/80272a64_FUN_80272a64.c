// Function: FUN_80272a64
// Entry: 80272a64
// Size: 248 bytes

void FUN_80272a64(int param_1)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  uint *puVar4;
  int iVar5;
  uint uVar6;
  
  uVar6 = DAT_803de264;
  if (param_1 == 1) {
    DAT_803de264 = DAT_803de264 & 0xfffffffc;
    FUN_80283f4c();
  }
  else if (param_1 < 1) {
    if (-1 < param_1) {
      DAT_803de264 = DAT_803de264 & 0xfffffffd | 1;
      FUN_80283f4c();
    }
  }
  else if (param_1 < 3) {
    DAT_803de264 = DAT_803de264 & 0xfffffffe | 2;
    FUN_80283f4c();
  }
  if (uVar6 != DAT_803de264) {
    iVar5 = 0;
    for (uVar6 = 0; uVar6 < DAT_803bd360; uVar6 = uVar6 + 1) {
      iVar2 = iVar5 + 0x114;
      iVar5 = iVar5 + 0x404;
      puVar4 = (uint *)(DAT_803de268 + iVar2);
      uVar1 = *puVar4;
      puVar3 = (uint *)(DAT_803de268 + iVar2);
      puVar3[1] = puVar4[1];
      *puVar3 = uVar1 | 0x2000;
    }
    FUN_80273870();
  }
  return;
}

