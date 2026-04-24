// Function: FUN_8011b3b4
// Entry: 8011b3b4
// Size: 544 bytes

void FUN_8011b3b4(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  short *psVar4;
  
  DAT_803dd6a8 = FUN_80023cc8(0x6c,5,0);
  DAT_803dd6ac = FUN_80023cc8(0x6c,5,0);
  DAT_803dd6c8 = FUN_80054d54(0x2dd);
  FUN_80019970(0x15);
  if (DAT_803dd6a0 == 0) {
    DAT_803dd6a0 = FUN_80019570(0xec);
  }
  iVar2 = 0;
  psVar4 = (short *)&DAT_803dba04;
  puVar3 = &DAT_803a8680;
  do {
    uVar1 = FUN_80054d54((int)*psVar4);
    *puVar3 = uVar1;
    psVar4 = psVar4 + 1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  iVar2 = FUN_80014930();
  if (iVar2 == 6) {
    FUN_8011a70c();
    DAT_803dd6b0 = DAT_803dd6a8;
    if (DAT_803db9fb != -1) {
      (**(code **)(*DAT_803dcaa0 + 8))();
    }
    DAT_803db9fb = '\x01';
    *(ushort *)(PTR_DAT_8031a7c8 + 0x16) = *(ushort *)(PTR_DAT_8031a7c8 + 0x16) & 0xbfff;
    PTR_DAT_8031a7c8[0x56] = 0;
    *(undefined2 *)(PTR_DAT_8031a7c8 + 0x3c) = 0x3d6;
    DAT_803dd6c5 = 0;
    (**(code **)(*DAT_803dcaa0 + 4))
              (PTR_DAT_8031a7c8,DAT_8031a7cc,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
    (**(code **)(*DAT_803dcaa0 + 0x18))(0);
    DAT_803dd6bc = 0;
    DAT_803dd6bd = 0;
    DAT_803dd6be = 0;
  }
  else {
    iVar2 = FUN_80014930();
    if (iVar2 != 5) {
      (**(code **)(*DAT_803dca4c + 0xc))(0x14,5);
    }
    FUN_8011a7e4(1);
  }
  iVar2 = 0;
  DAT_803dd6cc = 0;
  DAT_803dd6cd = 0;
  DAT_803dd6cf = 0;
  DAT_803dd6ce = 4;
  DAT_803dd6b4 = 0;
  puVar3 = &DAT_803a8658;
  do {
    uVar1 = FUN_80023cc8(5,5,0);
    *puVar3 = uVar1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 10);
  return;
}

