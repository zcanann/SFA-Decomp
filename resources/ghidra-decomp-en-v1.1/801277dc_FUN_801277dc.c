// Function: FUN_801277dc
// Entry: 801277dc
// Size: 2692 bytes

/* WARNING: Removing unreachable block (ram,0x80128240) */
/* WARNING: Removing unreachable block (ram,0x80128238) */
/* WARNING: Removing unreachable block (ram,0x80128230) */
/* WARNING: Removing unreachable block (ram,0x80128228) */
/* WARNING: Removing unreachable block (ram,0x80128220) */
/* WARNING: Removing unreachable block (ram,0x8012780c) */
/* WARNING: Removing unreachable block (ram,0x80127804) */
/* WARNING: Removing unreachable block (ram,0x801277fc) */
/* WARNING: Removing unreachable block (ram,0x801277f4) */
/* WARNING: Removing unreachable block (ram,0x801277ec) */

void FUN_801277dc(void)

{
  float fVar1;
  undefined uVar2;
  byte bVar3;
  short sVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  undefined *puVar15;
  undefined4 uVar16;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar18;
  ushort uVar17;
  double dVar19;
  undefined8 uVar20;
  double dVar21;
  double dVar22;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar23;
  double in_f30;
  double in_f31;
  double dVar24;
  double dVar25;
  longlong lVar26;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined auStack_d8 [56];
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined4 local_78;
  uint uStack_74;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar5 = FUN_80286834();
  FUN_80129d10();
  fVar1 = FLOAT_803e2b40 * FLOAT_803de3e0;
  local_a0 = (double)(longlong)(int)fVar1;
  dVar19 = (double)FUN_80294964();
  FLOAT_803de4d0 = (float)dVar19;
  FLOAT_803de3c8 = FLOAT_803de3c8 + FLOAT_803dc074;
  dVar19 = (double)FUN_80294b54();
  local_98 = (double)(longlong)(int)((double)FLOAT_803dc6b4 * dVar19);
  DAT_803de3d0 = (ushort)(int)((double)FLOAT_803dc6b4 * dVar19);
  dVar19 = (double)FUN_80294b54();
  iVar9 = (int)((double)FLOAT_803de3cc * dVar19 + (double)FLOAT_803dc6bc);
  local_90 = (double)(longlong)iVar9;
  DAT_803de3d2 = (ushort)iVar9;
  dVar19 = (double)FUN_80294b54();
  iVar9 = (int)((double)FLOAT_803dc6b8 * dVar19 + (double)FLOAT_803de43c);
  local_88 = (double)(longlong)iVar9;
  DAT_803de3d4 = (ushort)iVar9;
  FLOAT_803dc6a4 = (float)(DOUBLE_803e2cf0 * (double)FLOAT_803de3e0);
  dVar22 = (double)FLOAT_803dc6a4;
  FLOAT_803dc69c =
       (float)-(DOUBLE_803e2cf0 * (DOUBLE_803e2be0 - (double)FLOAT_803de3e0) - DOUBLE_803e2cf8);
  FUN_8011f234((double)FLOAT_803e2abc,(double)FLOAT_803dc69c,(double)FLOAT_803dc6a0,dVar22,
               DAT_803de3d0,DAT_803de3d2,DAT_803de3d4);
  iVar6 = FUN_8002b660(DAT_803de4e0);
  uVar16 = 1;
  iVar9 = DAT_803de4e0;
  FUN_8003ba50(0,0,0,0,DAT_803de4e0,1);
  *(ushort *)(iVar6 + 0x18) = *(ushort *)(iVar6 + 0x18) & 0xfff7;
  dVar19 = FUN_80019c38();
  sVar4 = (short)(int)fVar1;
  if (dVar19 == (double)FLOAT_803e2abc) {
    local_88 = (double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000);
    iVar6 = (int)((float)(local_88 - DOUBLE_803e2af8) * FLOAT_803de4d0);
    local_90 = (double)(longlong)iVar6;
    sVar4 = (short)iVar6;
    local_98 = (double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000);
    dVar21 = local_98 - DOUBLE_803e2af8;
    local_a0 = (double)CONCAT44(0x43300000,(int)DAT_803de3dc ^ 0x80000000);
    iVar6 = (int)(dVar21 * (DOUBLE_803e2d00 - (local_a0 - DOUBLE_803e2af8)) * DOUBLE_803e2d08);
    local_80 = (double)(longlong)iVar6;
    dVar19 = DOUBLE_803e2af8;
    uVar20 = FUN_80128260();
    if (DAT_803de444 == '\0') {
      iVar10 = (**(code **)(*DAT_803dd72c + 0x8c))();
      uVar8 = FUN_800ea540();
      dVar19 = FUN_800e9bec();
      dVar24 = (double)(float)(dVar19 / (double)FLOAT_803e2ca0);
      local_80 = (double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000);
      iVar6 = (int)((float)(local_80 - DOUBLE_803e2af8) * FLOAT_803de4d0);
      local_88 = (double)(longlong)iVar6;
      local_90 = (double)CONCAT44(0x43300000,(int)(short)iVar6 ^ 0x80000000);
      dVar21 = local_90 - DOUBLE_803e2af8;
      local_98 = (double)CONCAT44(0x43300000,(int)DAT_803de3dc ^ 0x80000000);
      uVar7 = (uint)(dVar21 * (DOUBLE_803e2d00 - (local_98 - DOUBLE_803e2af8)) * DOUBLE_803e2d08);
      local_a0 = (double)(longlong)(int)uVar7;
      bVar3 = (byte)uVar7;
      dVar19 = DOUBLE_803e2af8;
      FUN_8012845c(uVar5,bVar3);
      uVar11 = FUN_80020078(0x63c);
      uVar12 = FUN_80020078(0x4e9);
      uVar13 = FUN_80020078(0x5f3);
      uVar14 = FUN_80020078(0x5f4);
      puVar15 = &DAT_8031c7e0;
      for (cVar18 = '\0'; cVar18 < '\x04'; cVar18 = cVar18 + '\x01') {
        if ((int)cVar18 < (int)(uVar12 + uVar11 + uVar13 + uVar14 & 0xff)) {
          sVar4 = ((short)cVar18 & 1U) + 0x22;
        }
        else {
          sVar4 = 0x24;
        }
        *(short *)(puVar15 + 0xc0) = sVar4;
        puVar15 = puVar15 + 0x20;
      }
      uVar11 = FUN_80020078(0x91b);
      if (uVar11 == 0) {
        uVar11 = FUN_80020078(0x91a);
        if (uVar11 == 0) {
          uVar11 = FUN_80020078(0x919);
          if (uVar11 == 0) {
            DAT_803de3b4 = 10;
          }
          else {
            DAT_803de3b4 = 0x32;
          }
        }
        else {
          DAT_803de3b4 = 100;
        }
      }
      else {
        DAT_803de3b4 = 200;
      }
      if (DAT_803de3b4 == 0) {
        DAT_8031c940 = 0x25;
      }
      else {
        DAT_8031c940 = 0x4e;
      }
      FUN_8001b4f8(FUN_8011e974);
      uVar20 = FUN_80019940(0xff,0xff,0xff,bVar3);
      DAT_803dc6f2 = 0xff - DAT_803de3dc;
      FLOAT_803dc6f4 = FLOAT_803e2d20;
      FUN_8028fde8(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8,(int)auStack_d8,&DAT_803dc7d8
                   ,(uint)*(byte *)(iVar10 + 9),(uint)*(byte *)(iVar10 + 10),iVar9,uVar16,in_r9,
                   in_r10);
      uVar20 = FUN_80015e00(auStack_d8,0x93,0x14a,0xdc);
      uVar11 = (uint)DAT_803de3b4;
      if (uVar11 != 0) {
        FUN_8028fde8(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8,(int)auStack_d8,
                     &DAT_803dc7e0,DAT_803a9fd0,uVar11,iVar9,uVar16,in_r9,in_r10);
        uVar11 = 0x10e;
        uVar20 = FUN_80015e00(auStack_d8,0x93,0x140,0x10e);
      }
      FUN_8028fde8(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8,(int)auStack_d8,&DAT_803dc7e8
                   ,((uVar8 & 0xffff) * 100) / 0xbb & 0xff,uVar11,iVar9,uVar16,in_r9,in_r10);
      uVar5 = 300;
      uVar20 = FUN_80015e00(auStack_d8,0x93,0x130,300);
      iVar6 = (int)(dVar24 / (double)FLOAT_803e2d3c);
      local_80 = (double)(longlong)iVar6;
      if (iVar6 < 100) {
        uVar20 = FUN_8028fde8(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8,(int)auStack_d8,
                              &DAT_803dc7f0,iVar6,uVar5,iVar9,uVar16,in_r9,in_r10);
      }
      else {
        uVar20 = FUN_8028fde8(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8,(int)auStack_d8,
                              &DAT_803dc7f0,iVar6,uVar5,iVar9,uVar16,in_r9,in_r10);
      }
      local_80 = (double)(longlong)(int)(dVar24 / (double)FLOAT_803e2ca0);
      iVar10 = (int)(dVar24 / (double)FLOAT_803e2ca0) + iVar6 * -0x3c;
      FUN_8028fde8(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8,(int)auStack_d8,&DAT_803dc7f8
                   ,auStack_d8,iVar10,iVar9,uVar16,in_r9,in_r10);
      local_88 = (double)CONCAT44(0x43300000,iVar6 * 0xe10 ^ 0x80000000);
      dVar21 = (double)(float)(dVar24 - (double)(float)(local_88 - DOUBLE_803e2af8));
      local_90 = (double)CONCAT44(0x43300000,iVar10 * 0x3c ^ 0x80000000);
      iVar6 = (int)(dVar21 - (double)(float)(local_90 - DOUBLE_803e2af8));
      local_98 = (double)(longlong)iVar6;
      FUN_8028fde8(dVar21,DOUBLE_803e2af8,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8,(int)auStack_d8,
                   &DAT_803dc800,auStack_d8,iVar6,iVar9,uVar16,in_r9,in_r10);
      FUN_80015e00(auStack_d8,0x93,300,0x14a);
      FUN_8001b4f8(0);
      sVar4 = 0xe6 - DAT_803de3dc;
      dVar25 = (double)FLOAT_803e2c2c;
      dVar23 = (double)FLOAT_803e2bb0;
      dVar24 = (double)(longlong)(int)FLOAT_803e2d44;
      dVar21 = DOUBLE_803e2b08;
      for (uVar17 = 0; uVar17 < 7; uVar17 = uVar17 + 1) {
        local_80 = (double)CONCAT44(0x43300000,(uint)uVar17);
        local_88._4_4_ = SUB84(dVar24,0);
        uVar8 = local_88._4_4_;
        local_88 = dVar24;
        FUN_8011f088((double)(float)(dVar25 * (double)(float)(local_80 - dVar21) + dVar23),
                     (double)FLOAT_803e2d40,DAT_803a966c,(int)sVar4,bVar3,uVar8,0);
      }
      lVar26 = (longlong)(int)FLOAT_803e2d44;
      dVar24 = (double)FLOAT_803e2c2c;
      dVar23 = (double)FLOAT_803e2bb0;
      dVar21 = DOUBLE_803e2b08;
      for (uVar8 = 0; uVar11 = uVar8 & 0xffff, (int)uVar11 < DAT_803a9fe0 >> 2; uVar8 = uVar8 + 1) {
        if ((int)uVar11 < (int)DAT_803a9fc4 >> 2) {
          iVar9 = 0x16;
        }
        else if ((int)DAT_803a9fc4 >> 2 < (int)uVar11) {
          iVar9 = 0x12;
        }
        else {
          iVar9 = (DAT_803a9fc4 & 3) + 0x12;
        }
        local_80 = (double)CONCAT44(0x43300000,uVar8 & 0xffff);
        dVar25 = (double)(float)(dVar24 * (double)(float)(local_80 - dVar21) + dVar23);
        for (cVar18 = '\x14'; -1 < cVar18; cVar18 = cVar18 + -4) {
          local_80._4_4_ = (uint)lVar26;
          uVar11 = local_80._4_4_;
          local_80 = (double)lVar26;
          FUN_8011f088(dVar25,(double)FLOAT_803e2d40,(&DAT_803a9610)[iVar9],
                       (int)(short)((0xff - cVar18) - DAT_803de3dc),bVar3,uVar11,0);
        }
      }
      local_80 = (double)CONCAT44(0x43300000,DAT_803dc738 ^ 0x80000000);
      local_88 = (double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000);
      FUN_8011f088((double)(float)(local_80 - DOUBLE_803e2af8),
                   (double)(float)(local_88 - DOUBLE_803e2af8),DAT_803a96cc,0x100 - DAT_803de3dc,
                   bVar3,0x100,0);
      local_90 = (double)CONCAT44(0x43300000,DAT_803dc738 + 0x18 ^ 0x80000000);
      local_98 = (double)CONCAT44(0x43300000,DAT_803dc73c ^ 0x80000000);
      FUN_8011ee20((double)(float)(local_90 - DOUBLE_803e2af8),
                   (double)(float)(local_98 - DOUBLE_803e2af8),DAT_803a96c8,0x100 - DAT_803de3dc,
                   bVar3,0x100,0x66,0x12,0);
      local_a0 = (double)CONCAT44(0x43300000,DAT_803dc738 + 0x7e ^ 0x80000000);
      uStack_74 = DAT_803dc73c ^ 0x80000000;
      local_78 = 0x43300000;
      dVar21 = (double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e2af8);
      FUN_8011f088((double)(float)(local_a0 - DOUBLE_803e2af8),dVar21,DAT_803a96d0,
                   0x100 - DAT_803de3dc,bVar3,0x100,0);
      uVar20 = FUN_80121f30(uVar7 & 0xff,0x100 - DAT_803de3dc,1);
      DAT_803de4a4 = &DAT_8031c7e0;
      FUN_801287ac(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8);
    }
    else {
      for (cVar18 = '\x14'; -1 < cVar18; cVar18 = cVar18 + -4) {
        iVar9 = (int)(short)((0xf0 - cVar18) - DAT_803de3dc);
        uVar2 = (undefined)iVar6;
        FUN_8011ee20((double)FLOAT_803e2d14,(double)FLOAT_803e2d30,DAT_803a9780,iVar9,uVar2,0x100,
                     400,4,0);
        FUN_8011ee20((double)FLOAT_803e2b4c,(double)FLOAT_803e2d34,DAT_803a9780,iVar9,uVar2,0x100,
                     0xf0,4,0);
        dVar21 = (double)FLOAT_803e2d38;
        uVar20 = FUN_8011ee20((double)FLOAT_803e2b4c,dVar21,DAT_803a9780,iVar9,uVar2,0x100,0xf0,4,0)
        ;
      }
      DAT_803de4a4 = &DAT_8031c9e0;
      FUN_801287ac(uVar20,dVar21,dVar19,dVar22,in_f5,in_f6,in_f7,in_f8);
    }
    iVar9 = FUN_8002b660(iRam803de4e4);
    FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
    *(ushort *)(iVar9 + 0x18) = *(ushort *)(iVar9 + 0x18) & 0xfff7;
    FUN_8000f478(0);
    FUN_8000f584();
    FUN_8000fc5c((double)FLOAT_803de47c);
    FUN_8000fb20();
    FUN_8000f7a0();
  }
  else {
    uVar7 = FUN_80022264(0,0x1e);
    uVar8 = FUN_80022264(0,0x1e);
    FUN_8011ebbc((double)FLOAT_803e2d10,(double)FLOAT_803e2d14,DAT_803a9760,0xff,
                 (char)((int)sVar4 / 2),0x230,400,uVar8 << 1,uVar7 << 1);
    iVar9 = FUN_8002b660(iRam803de4e4);
    FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
    *(ushort *)(iVar9 + 0x18) = *(ushort *)(iVar9 + 0x18) & 0xfff7;
    FUN_8000f478(0);
    FUN_8000f584();
    FUN_8000fc5c((double)FLOAT_803de47c);
    FUN_8000fb20();
    FUN_8000f7a0();
  }
  FUN_80286880();
  return;
}

