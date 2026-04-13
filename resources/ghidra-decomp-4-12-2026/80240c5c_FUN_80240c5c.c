// Function: FUN_80240c5c
// Entry: 80240c5c
// Size: 952 bytes

undefined4 FUN_80240c5c(void)

{
  int iVar1;
  undefined4 uVar2;
  uint *puVar3;
  uint uVar4;
  longlong lVar5;
  ulonglong uVar6;
  
  if (DAT_803dea68 != 0) {
    return 0x80330000;
  }
  DAT_803dea68 = 1;
  lVar5 = FUN_802473d4();
  DAT_803dea80 = (undefined4)((ulonglong)lVar5 >> 0x20);
  DAT_803dea84 = (undefined4)lVar5;
  FUN_80243e74();
  FUN_80240aa0();
  FUN_80240ac8();
  DAT_803dea5c = (uint *)0x0;
  DAT_803dea58 = -0x80000000;
  if (DAT_800000f4 == 0) {
    if (DAT_80000034 != 0) {
      DAT_803dea60 = (uint)DAT_800030e8;
      DAT_803dea5c = &DAT_803dea60;
      DAT_803dec54 = (uint)DAT_800030e9;
    }
  }
  else {
    DAT_803dea5c = (uint *)(DAT_800000f4 + 0xc);
    DAT_803dec54 = *(uint *)(DAT_800000f4 + 0x24);
    DAT_800030e8 = (byte)*DAT_803dea5c;
    DAT_800030e9 = (byte)DAT_803dec54;
  }
  DAT_803deb7c = 1;
  iVar1 = DAT_80000030;
  if (DAT_80000030 == 0) {
    iVar1 = -0x7fc04f00;
  }
  FUN_80241e00(iVar1);
  if (((*(int *)(DAT_803dea58 + 0x30) == 0) && (DAT_803dea5c != (uint *)0x0)) && (*DAT_803dea5c < 2)
     ) {
    FUN_80241e00(0x803f9100);
  }
  iVar1 = *(int *)(DAT_803dea58 + 0x34);
  if (iVar1 == 0) {
    iVar1 = -0x7e900000;
  }
  FUN_80241df8(iVar1);
  FUN_80241014();
  FUN_80246350();
  FUN_8024142c();
  FUN_802446e0();
  FUN_80243ef0();
  FUN_80243ec0(0x16,&LAB_80245248);
  FUN_80242f78();
  FUN_80242664();
  FUN_80254b20();
  FUN_802529f8();
  FUN_8024574c();
  FUN_802463b4();
  FUN_80241e08();
  FUN_80240a7c();
  FUN_80240a84();
  puVar3 = (uint *)(DAT_803dea58 + 0x2c);
  if ((*puVar3 & 0x10000000) == 0) {
    *puVar3 = 1;
  }
  else {
    *puVar3 = 0x10000004;
  }
  uVar4 = DAT_cc00302c;
  *(uint *)(DAT_803dea58 + 0x2c) = *(int *)(DAT_803dea58 + 0x2c) + (uVar4 >> 0x1c);
  if (DAT_803dea78 == 0) {
    FUN_80244abc();
  }
  FUN_8007d858();
  FUN_8007d858();
  FUN_8007d858();
  if ((DAT_803dea58 == 0) || (uVar4 = *(uint *)(DAT_803dea58 + 0x2c), uVar4 == 0)) {
    uVar4 = 0x10000002;
  }
  if ((uVar4 & 0x10000000) == 0) {
    FUN_8007d858();
  }
  else if (uVar4 == 0x10000002) {
    FUN_8007d858();
  }
  else {
    if ((int)uVar4 < 0x10000002) {
      if (uVar4 == 0x10000000) {
        FUN_8007d858();
        goto LAB_80240f4c;
      }
      if (0xfffffff < (int)uVar4) {
        FUN_8007d858();
        goto LAB_80240f4c;
      }
    }
    else if ((int)uVar4 < 0x10000004) {
      FUN_8007d858();
      goto LAB_80240f4c;
    }
    FUN_8007d858();
  }
LAB_80240f4c:
  FUN_8007d858();
  FUN_80241de8();
  FUN_80241df0();
  FUN_8007d858();
  if ((DAT_803dea5c != (uint *)0x0) && (1 < *DAT_803dea5c)) {
    FUN_8028d210();
  }
  FUN_80240af8();
  uVar6 = FUN_80243e88();
  uVar2 = (undefined4)(uVar6 >> 0x20);
  if (DAT_803dea78 == 0) {
    FUN_80249958();
    if (DAT_803dea64 == 0) {
      FUN_802420b0(0x803adf80,0x20);
      uVar2 = FUN_8024b970((undefined4 *)&DAT_803adfa0,&DAT_803adf80,&LAB_80240c20);
    }
    else {
      uVar2 = 0x80000000;
      DAT_800030e6 = 0x9000;
    }
  }
  return uVar2;
}

