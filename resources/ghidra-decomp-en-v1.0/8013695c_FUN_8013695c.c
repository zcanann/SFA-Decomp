// Function: FUN_8013695c
// Entry: 8013695c
// Size: 228 bytes

void FUN_8013695c(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  short *psVar4;
  
  DAT_803dbc08 = 0xff;
  DAT_803dd990 = 0;
  DAT_803dbc09 = 0xff;
  DAT_803dd991 = 0;
  if (DAT_803dc968 == '\0') {
    DAT_803dd9d4 = FUN_80054d54(0xc5);
  }
  else {
    DAT_803dd9d4 = FUN_80054d54(0x647);
  }
  FLOAT_803dd9d0 = FLOAT_803e2318;
  FLOAT_803dd9cc = FLOAT_803e2318;
  FUN_80246e54(&DAT_803a9fe4);
  iVar2 = 0;
  psVar4 = &DAT_8031cde8;
  puVar3 = &DAT_803a9f98;
  do {
    uVar1 = FUN_80054d54((int)*psVar4);
    *puVar3 = uVar1;
    psVar4 = psVar4 + 1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x13);
  DAT_803dd992 = 0;
  DAT_803dd9ab = 1;
  DAT_803dd9ac = 0;
  FLOAT_803dd9b0 = FLOAT_803e2318;
  FLOAT_803dd9b4 = FLOAT_803e2318;
  FLOAT_803dd9c4 = FLOAT_803e22f8;
  return;
}

