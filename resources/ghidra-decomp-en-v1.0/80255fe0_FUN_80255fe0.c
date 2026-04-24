// Function: FUN_80255fe0
// Entry: 80255fe0
// Size: 272 bytes

void FUN_80255fe0(uint *param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8024377c();
  DAT_803de0b8 = param_1;
  if (param_1 == DAT_803de0bc) {
    *(uint *)(DAT_803de0a8 + 0xc) = *param_1 & 0x3fffffff;
    *(uint *)(DAT_803de0a8 + 0x10) = param_1[1] & 0x3fffffff;
    *(uint *)(DAT_803de0a8 + 0x14) = param_1[6] & 0x3bffffe0;
    DAT_803de0c4 = '\x01';
    FUN_802566c8(1,1);
    FUN_8025667c(1,0);
    FUN_80256638(1);
  }
  else {
    if (DAT_803de0c4 != '\0') {
      FUN_80256638(0);
      DAT_803de0c4 = '\0';
    }
    FUN_8025667c(0,0);
    *(uint *)(DAT_803de0a8 + 0xc) = *param_1 & 0x3fffffff;
    *(uint *)(DAT_803de0a8 + 0x10) = param_1[1] & 0x3fffffff;
    *(uint *)(DAT_803de0a8 + 0x14) = param_1[6] & 0x3bffffe0;
  }
  sync(0);
  FUN_802437a4(uVar1);
  return;
}

