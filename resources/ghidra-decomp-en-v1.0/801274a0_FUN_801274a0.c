// Function: FUN_801274a0
// Entry: 801274a0
// Size: 2692 bytes

/* WARNING: Removing unreachable block (ram,0x80127efc) */
/* WARNING: Removing unreachable block (ram,0x80127eec) */
/* WARNING: Removing unreachable block (ram,0x80127ee4) */
/* WARNING: Removing unreachable block (ram,0x80127ef4) */
/* WARNING: Removing unreachable block (ram,0x80127f04) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_801274a0(void)

{
  uint uVar1;
  float fVar2;
  uint uVar3;
  short sVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined *puVar13;
  char cVar15;
  ushort uVar14;
  undefined4 uVar16;
  double dVar17;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar18;
  undefined8 in_f29;
  double dVar19;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar20;
  longlong lVar21;
  undefined auStack216 [56];
  double local_a0;
  double local_98;
  double local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined4 local_78;
  uint uStack116;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar5 = FUN_802860d0();
  FUN_801299d4();
  fVar2 = FLOAT_803e1ec0 * FLOAT_803dd760;
  local_a0 = (double)(longlong)(int)fVar2;
  dVar17 = (double)FUN_80294204((double)((FLOAT_803e1ec8 * FLOAT_803dd7bc) / FLOAT_803e1e94));
  FLOAT_803dd850 = (float)dVar17;
  FLOAT_803dd748 = FLOAT_803dd748 + FLOAT_803db414;
  dVar17 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba40));
  local_98 = (double)(longlong)(int)((double)FLOAT_803dba4c * dVar17);
  DAT_803dd750 = (undefined2)(int)((double)FLOAT_803dba4c * dVar17);
  dVar17 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba44));
  iVar6 = (int)((double)FLOAT_803dd74c * dVar17 + (double)FLOAT_803dba54);
  local_90 = (double)(longlong)iVar6;
  DAT_803dd752 = (undefined2)iVar6;
  dVar17 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba48));
  uVar1 = (uint)((double)FLOAT_803dba50 * dVar17 + (double)FLOAT_803dd7bc);
  local_88 = (double)(longlong)(int)uVar1;
  DAT_803dd754 = (undefined2)uVar1;
  FLOAT_803dba3c = (float)(DOUBLE_803e2070 * (double)FLOAT_803dd760);
  FLOAT_803dba34 =
       (float)-(DOUBLE_803e2070 * (DOUBLE_803e1f60 - (double)FLOAT_803dd760) - DOUBLE_803e2078);
  FUN_8011ef50((double)FLOAT_803e1e3c,(double)FLOAT_803dba34,(double)FLOAT_803dba38,DAT_803dd750,
               DAT_803dd752,uVar1 & 0xffff);
  iVar6 = FUN_8002b588(DAT_803dd860);
  FUN_8003b958(0,0,0,0,DAT_803dd860,1);
  *(ushort *)(iVar6 + 0x18) = *(ushort *)(iVar6 + 0x18) & 0xfff7;
  dVar17 = (double)FUN_80019c00();
  sVar4 = (short)(int)fVar2;
  if (dVar17 == (double)FLOAT_803e1e3c) {
    local_88 = (double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000);
    iVar6 = (int)((float)(local_88 - DOUBLE_803e1e78) * FLOAT_803dd850);
    local_90 = (double)(longlong)iVar6;
    local_98 = (double)CONCAT44(0x43300000,(int)(short)iVar6 ^ 0x80000000);
    local_a0 = (double)CONCAT44(0x43300000,(int)DAT_803dd75c ^ 0x80000000);
    uVar1 = (uint)((local_98 - DOUBLE_803e1e78) * (DOUBLE_803e2080 - (local_a0 - DOUBLE_803e1e78)) *
                  DOUBLE_803e2088);
    local_80 = (double)(longlong)(int)uVar1;
    FUN_80127f24(uVar1);
    if (DAT_803dd7c4 == '\0') {
      iVar7 = (**(code **)(*DAT_803dcaac + 0x8c))();
      uVar8 = FUN_800ea2bc();
      dVar17 = (double)FUN_800e9968();
      dVar17 = (double)(float)(dVar17 / (double)FLOAT_803e2020);
      local_80 = (double)CONCAT44(0x43300000,(int)(short)iVar6 ^ 0x80000000);
      iVar6 = (int)((float)(local_80 - DOUBLE_803e1e78) * FLOAT_803dd850);
      local_88 = (double)(longlong)iVar6;
      local_90 = (double)CONCAT44(0x43300000,(int)(short)iVar6 ^ 0x80000000);
      local_98 = (double)CONCAT44(0x43300000,(int)DAT_803dd75c ^ 0x80000000);
      uVar1 = (uint)((local_90 - DOUBLE_803e1e78) * (DOUBLE_803e2080 - (local_98 - DOUBLE_803e1e78))
                    * DOUBLE_803e2088);
      local_a0 = (double)(longlong)(int)uVar1;
      FUN_80128120(uVar5,uVar1 & 0xff);
      iVar9 = FUN_8001ffb4(0x63c);
      iVar10 = FUN_8001ffb4(0x4e9);
      iVar11 = FUN_8001ffb4(0x5f3);
      iVar12 = FUN_8001ffb4(0x5f4);
      puVar13 = &DAT_8031bb90;
      for (cVar15 = '\0'; cVar15 < '\x04'; cVar15 = cVar15 + '\x01') {
        if ((int)cVar15 < (int)(iVar10 + iVar9 + iVar11 + iVar12 & 0xffU)) {
          sVar4 = ((short)cVar15 & 1U) + 0x22;
        }
        else {
          sVar4 = 0x24;
        }
        *(short *)(puVar13 + 0xc0) = sVar4;
        puVar13 = puVar13 + 0x20;
      }
      iVar9 = FUN_8001ffb4(0x91b);
      if (iVar9 == 0) {
        iVar9 = FUN_8001ffb4(0x91a);
        if (iVar9 == 0) {
          iVar9 = FUN_8001ffb4(0x919);
          if (iVar9 == 0) {
            DAT_803dd734 = '\n';
          }
          else {
            DAT_803dd734 = '2';
          }
        }
        else {
          DAT_803dd734 = 'd';
        }
      }
      else {
        DAT_803dd734 = -0x38;
      }
      if (DAT_803dd734 == '\0') {
        DAT_8031bcf0 = 0x25;
      }
      else {
        DAT_8031bcf0 = 0x4e;
      }
      FUN_8001b444(FUN_8011e690);
      FUN_80019908(0xff,0xff,0xff,uVar1 & 0xff);
      DAT_803dba8a = 0xff - DAT_803dd75c;
      FLOAT_803dba8c = FLOAT_803e20a0;
      FUN_8028f688(auStack216,&DAT_803dbb70,*(undefined *)(iVar7 + 9),*(undefined *)(iVar7 + 10));
      FUN_80015dc8(auStack216,0x93,0x14a,0xdc);
      if (DAT_803dd734 != '\0') {
        FUN_8028f688(auStack216,&DAT_803dbb78,DAT_803a9370);
        FUN_80015dc8(auStack216,0x93,0x140,0x10e);
      }
      FUN_8028f688(auStack216,&DAT_803dbb80,((uVar8 & 0xffff) * 100) / 0xbb & 0xff);
      FUN_80015dc8(auStack216,0x93,0x130,300);
      iVar7 = (int)(dVar17 / (double)FLOAT_803e20b0);
      local_80 = (double)(longlong)iVar7;
      if (iVar7 < 100) {
        FUN_8028f688(auStack216,&DAT_803dbb88,iVar7);
      }
      else {
        FUN_8028f688(auStack216,&DAT_803dbb88,iVar7);
      }
      local_80 = (double)(longlong)(int)(dVar17 / (double)FLOAT_803e2020);
      iVar9 = (int)(dVar17 / (double)FLOAT_803e2020) + iVar7 * -0x3c;
      FUN_8028f688(auStack216,&DAT_803dbb90,auStack216,iVar9);
      local_88 = (double)CONCAT44(0x43300000,iVar7 * 0xe10 ^ 0x80000000);
      local_90 = (double)CONCAT44(0x43300000,iVar9 * 0x3c ^ 0x80000000);
      iVar7 = (int)((float)(dVar17 - (double)(float)(local_88 - DOUBLE_803e1e78)) -
                   (float)(local_90 - DOUBLE_803e1e78));
      local_98 = (double)(longlong)iVar7;
      FUN_8028f688(auStack216,&DAT_803dbb98,auStack216,iVar7);
      FUN_80015dc8(auStack216,0x93,300,0x14a);
      FUN_8001b444(0);
      sVar4 = 0xe6 - DAT_803dd75c;
      dVar20 = (double)FLOAT_803e1fac;
      dVar19 = (double)FLOAT_803e1f30;
      dVar18 = (double)(longlong)(int)FLOAT_803e20b8;
      dVar17 = DOUBLE_803e1e88;
      for (uVar14 = 0; uVar14 < 7; uVar14 = uVar14 + 1) {
        local_80 = (double)CONCAT44(0x43300000,(uint)uVar14);
        local_88._4_4_ = SUB84(dVar18,0);
        local_88 = dVar18;
        FUN_8011eda4((double)(float)(dVar20 * (double)(float)(local_80 - dVar17) + dVar19),
                     (double)FLOAT_803e20b4,DAT_803a8a0c,(int)sVar4,uVar1 & 0xff,local_88._4_4_,0);
      }
      lVar21 = (longlong)(int)FLOAT_803e20b8;
      dVar18 = (double)FLOAT_803e1fac;
      dVar19 = (double)FLOAT_803e1f30;
      dVar17 = DOUBLE_803e1e88;
      for (uVar8 = 0; uVar3 = uVar8 & 0xffff, (int)uVar3 < DAT_803a9380 >> 2; uVar8 = uVar8 + 1) {
        if ((int)uVar3 < (int)DAT_803a9364 >> 2) {
          iVar7 = 0x16;
        }
        else if ((int)DAT_803a9364 >> 2 < (int)uVar3) {
          iVar7 = 0x12;
        }
        else {
          iVar7 = (DAT_803a9364 & 3) + 0x12;
        }
        local_80 = (double)CONCAT44(0x43300000,uVar8 & 0xffff);
        dVar20 = (double)(float)(dVar18 * (double)(float)(local_80 - dVar17) + dVar19);
        for (cVar15 = '\x14'; -1 < cVar15; cVar15 = cVar15 + -4) {
          local_80._4_4_ = (undefined4)lVar21;
          local_80 = (double)lVar21;
          FUN_8011eda4(dVar20,(double)FLOAT_803e20b4,(&DAT_803a89b0)[iVar7],
                       (int)(short)((0xff - cVar15) - DAT_803dd75c),uVar1 & 0xff,local_80._4_4_,0);
        }
      }
      local_80 = (double)CONCAT44(0x43300000,DAT_803dbad0 ^ 0x80000000);
      local_88 = (double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000);
      FUN_8011eda4((double)(float)(local_80 - DOUBLE_803e1e78),
                   (double)(float)(local_88 - DOUBLE_803e1e78),DAT_803a8a6c,0x100 - DAT_803dd75c,
                   uVar1 & 0xff,0x100,0);
      local_90 = (double)CONCAT44(0x43300000,DAT_803dbad0 + 0x18 ^ 0x80000000);
      local_98 = (double)CONCAT44(0x43300000,DAT_803dbad4 ^ 0x80000000);
      FUN_8011eb3c((double)(float)(local_90 - DOUBLE_803e1e78),
                   (double)(float)(local_98 - DOUBLE_803e1e78),DAT_803a8a68,0x100 - DAT_803dd75c,
                   uVar1 & 0xff,0x100,0x66,0x12,0);
      local_a0 = (double)CONCAT44(0x43300000,DAT_803dbad0 + 0x7e ^ 0x80000000);
      uStack116 = DAT_803dbad4 ^ 0x80000000;
      local_78 = 0x43300000;
      FUN_8011eda4((double)(float)(local_a0 - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e1e78),
                   DAT_803a8a70,0x100 - DAT_803dd75c,uVar1 & 0xff,0x100,0);
      FUN_80121c4c(uVar1 & 0xff,0x100 - DAT_803dd75c,1);
      DAT_803dd824 = &DAT_8031bb90;
      FUN_80128470(iVar6);
    }
    else {
      for (cVar15 = '\x14'; -1 < cVar15; cVar15 = cVar15 + -4) {
        iVar7 = (int)(short)((0xf0 - cVar15) - DAT_803dd75c);
        FUN_8011eb3c((double)FLOAT_803e2094,(double)FLOAT_803e20a4,DAT_803a8b20,iVar7,uVar1 & 0xff,
                     0x100,400,4,0);
        FUN_8011eb3c((double)FLOAT_803e1ecc,(double)FLOAT_803e20a8,DAT_803a8b20,iVar7,uVar1 & 0xff,
                     0x100,0xf0,4,0);
        FUN_8011eb3c((double)FLOAT_803e1ecc,(double)FLOAT_803e20ac,DAT_803a8b20,iVar7,uVar1 & 0xff,
                     0x100,0xf0,4,0);
      }
      DAT_803dd824 = &DAT_8031bd90;
      FUN_80128470(iVar6);
    }
    iVar6 = FUN_8002b588(uRam803dd864);
    FUN_8003b958(0,0,0,0,uRam803dd864,1);
    *(ushort *)(iVar6 + 0x18) = *(ushort *)(iVar6 + 0x18) & 0xfff7;
    FUN_8000f458(0);
    FUN_8000f564();
    FUN_8000fc3c((double)FLOAT_803dd7fc);
    FUN_8000fb00();
    FUN_8000f780();
  }
  else {
    iVar6 = FUN_800221a0(0,0x1e);
    iVar7 = FUN_800221a0(0,0x1e);
    FUN_8011e8d8((double)FLOAT_803e2090,(double)FLOAT_803e2094,DAT_803a8b00,0xff,
                 (int)sVar4 / 2 & 0xff,0x230,400,iVar7 << 1,iVar6 << 1);
    iVar6 = FUN_8002b588(uRam803dd864);
    FUN_8003b958(0,0,0,0,uRam803dd864,1);
    *(ushort *)(iVar6 + 0x18) = *(ushort *)(iVar6 + 0x18) & 0xfff7;
    FUN_8000f458(0);
    FUN_8000f564();
    FUN_8000fc3c((double)FLOAT_803dd7fc);
    FUN_8000fb00();
    FUN_8000f780();
  }
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  __psq_l0(auStack24,uVar16);
  __psq_l1(auStack24,uVar16);
  __psq_l0(auStack40,uVar16);
  __psq_l1(auStack40,uVar16);
  __psq_l0(auStack56,uVar16);
  __psq_l1(auStack56,uVar16);
  __psq_l0(auStack72,uVar16);
  __psq_l1(auStack72,uVar16);
  FUN_8028611c();
  return;
}

