// Function: FUN_80128470
// Entry: 80128470
// Size: 1548 bytes

/* WARNING: Removing unreachable block (ram,0x80128a5c) */

void FUN_80128470(void)

{
  int iVar1;
  short sVar2;
  undefined4 uVar3;
  undefined *puVar4;
  ushort uVar6;
  uint uVar5;
  int iVar7;
  char cVar8;
  short sVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  int local_e8;
  int local_e4;
  undefined auStack224 [4];
  undefined auStack220 [4];
  undefined4 local_d8;
  uint uStack212;
  longlong local_d0;
  double local_c8;
  double local_c0;
  longlong local_b8;
  undefined4 local_b0;
  uint uStack172;
  undefined4 local_a8;
  uint uStack164;
  longlong local_a0;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  longlong local_88;
  longlong local_80;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar3 = FUN_802860d4();
  FUN_8001b444(FUN_8011e690);
  FLOAT_803dba8c = FLOAT_803e20a0;
  if (FLOAT_803e1e3c < FLOAT_803dd7bc) {
    cVar8 = '\0';
    for (puVar4 = DAT_803dd824; -1 < *(int *)(puVar4 + 0x18); puVar4 = puVar4 + 0x20) {
      cVar8 = cVar8 + '\x01';
    }
    while (cVar8 = cVar8 + -1, -1 < cVar8) {
      if ((int)cVar8 != DAT_803dd7d8) {
        FUN_80128a7c(cVar8,uVar3,0);
      }
    }
  }
  else {
    cVar8 = '\0';
    for (iVar7 = 0; -1 < *(int *)(DAT_803dd824 + iVar7 + 0x18); iVar7 = iVar7 + 0x20) {
      if ((int)cVar8 != DAT_803dd7d8) {
        FUN_80128a7c(cVar8,uVar3,0);
      }
      cVar8 = cVar8 + '\x01';
    }
  }
  FUN_80128a7c(DAT_803dd7d8 & 0xff,uVar3,0);
  dVar13 = (double)FLOAT_803dbac0;
  dVar12 = (double)FUN_80293e80((double)((FLOAT_803e1ec8 * FLOAT_803e2104 * FLOAT_803dd748) /
                                        FLOAT_803e1e94));
  uStack212 = (int)(short)uVar3 ^ 0x80000000;
  local_d8 = 0x43300000;
  iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack212) - DOUBLE_803e1e78) *
               (float)(dVar13 * dVar12 + dVar13));
  local_d0 = (longlong)iVar7;
  FUN_80128a7c(DAT_803dd7d8 & 0xff,iVar7,4);
  iVar10 = (int)(short)uVar3;
  local_c8 = (double)CONCAT44(0x43300000,iVar10 * (0x200 - DAT_803dd75c) ^ 0x80000000);
  iVar7 = (int)((local_c8 - DOUBLE_803e1e78) * DOUBLE_803e2088);
  local_c0 = (double)(longlong)iVar7;
  FUN_80019908(0xff,0xff,0xff,iVar7);
  DAT_803dba8a = 0x100 - DAT_803dd75c;
  if ((DAT_803dd780 < 0xb) && (7 < DAT_803dd780)) {
    FUN_80016810(1000,200,0x154);
  }
  else {
    FUN_80016810(0x3dd,200,0x154);
  }
  if (DAT_803dd75c != 0) {
    local_c0 = (double)CONCAT44(0x43300000,iVar10 * DAT_803dd75c ^ 0x80000000);
    iVar7 = (int)((local_c0 - DOUBLE_803e1e78) * DOUBLE_803e2088);
    local_c8 = (double)(longlong)iVar7;
    FUN_80019908(0xff,0xff,0xff,iVar7);
    DAT_803dba8a = DAT_803dd75c + -0xff;
    if (DAT_803dd824 == &DAT_8031b818) {
      FUN_8001628c(*(undefined4 *)(DAT_803dd7d8 * 0x20 + -0x7fce47d4),0,0,auStack220,auStack224,
                   &local_e4,&local_e8);
      sVar2 = 0xdc - (short)((local_e8 - local_e4) / 2);
    }
    else {
      sVar2 = 0xdc;
    }
    FUN_80016810(*(undefined4 *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 0x14),200,(int)sVar2);
    FUN_80016810(0x3de,200,0x154);
  }
  if (DAT_803dd75c == 0) {
    local_c0 = (double)(longlong)(int)FLOAT_803e1f34;
    local_c8 = (double)CONCAT44(0x43300000,(uint)(byte)DAT_803dd824[DAT_803dd7d8 * 0x20 + 8]);
    uStack164 = (uint)((float)(DOUBLE_803e2108 *
                              (double)*(float *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 0x10)) *
                      (float)(local_c8 - DOUBLE_803e1e88));
    local_d0 = (longlong)(int)uStack164;
    uStack212 = (uint)(byte)DAT_803dd824[DAT_803dd7d8 * 0x20 + 9];
    local_d8 = 0x43300000;
    uStack140 = (uint)((float)(DOUBLE_803e2108 *
                              (double)*(float *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 0x10)) *
                      (float)((double)CONCAT44(0x43300000,uStack212) - DOUBLE_803e1e88));
    local_b8 = (longlong)(int)uStack140;
    uStack172 = (uint)*(ushort *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 2) +
                (int)(char)DAT_803dd824[DAT_803dd7d8 * 0x20 + 0xb] ^ 0x80000000;
    local_b0 = 0x43300000;
    uStack164 = uStack164 & 0xff;
    local_a8 = 0x43300000;
    iVar7 = (int)(((float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e1e78) -
                  FLOAT_803e2110) -
                 (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803e1e88));
    local_a0 = (longlong)iVar7;
    uStack68 = (uint)(short)((short)uStack164 +
                            (short)((uint)*(ushort *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 2) +
                                   (int)(char)DAT_803dd824[DAT_803dd7d8 * 0x20 + 0xb]));
    uStack148 = (uint)*(ushort *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 4);
    local_98 = 0x43300000;
    uStack140 = uStack140 & 0xff;
    local_90 = 0x43300000;
    iVar1 = (int)(((float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e1e88) -
                  FLOAT_803e2114) -
                 (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e1e88));
    local_88 = (longlong)iVar1;
    uStack60 = (uint)(short)((short)uStack140 + *(ushort *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 4))
    ;
    uVar5 = (uint)FLOAT_803dd748;
    local_80 = (longlong)(int)uVar5;
    uVar6 = (ushort)uVar5 & 0x3f;
    if ((uVar5 & 0x20) != 0) {
      uVar6 = uVar6 ^ 0x3f;
    }
    uVar5 = iVar10 * 0xc0;
    iVar10 = (int)(short)uVar6 *
             (((int)uVar5 >> 8) + (uint)((int)uVar5 < 0 && (uVar5 & 0xff) != 0) + 0x40);
    iVar10 = iVar10 / 0x1f + (iVar10 >> 0x1f);
    uVar6 = (short)iVar10 - (short)(iVar10 >> 0x1f);
    sVar9 = (short)iVar7;
    uStack116 = (int)sVar9 ^ 0x80000000;
    local_78 = 0x43300000;
    sVar2 = (short)iVar1;
    uStack108 = (int)sVar2 ^ 0x80000000;
    local_70 = 0x43300000;
    uVar5 = (int)FLOAT_803e1f34 & 0xffff;
    FUN_8011eda4((double)(float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e1e78),
                 (double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e1e78),
                 DAT_803a8a30,0x100,uVar6 & 0xff,uVar5,0);
    uStack100 = uStack68 ^ 0x80000000;
    local_68 = 0x43300000;
    uStack92 = (int)sVar2 ^ 0x80000000;
    local_60 = 0x43300000;
    FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e1e78),
                 (double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e1e78),
                 DAT_803a8a30,0x100,uVar6 & 0xff,uVar5,0x12,10,1);
    uStack84 = (int)sVar9 ^ 0x80000000;
    local_58 = 0x43300000;
    uStack76 = uStack60 ^ 0x80000000;
    local_50 = 0x43300000;
    FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e1e78),
                 (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e1e78),
                 DAT_803a8a30,0x100,uVar6 & 0xff,uVar5,0x12,10,2);
    uStack68 = uStack68 ^ 0x80000000;
    local_48 = 0x43300000;
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    FUN_8011eb3c((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1e78),
                 (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1e78),
                 DAT_803a8a30,0x100,uVar6 & 0xff,uVar5,0x12,10,3);
  }
  FUN_8001b444(0);
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286120();
  return;
}

