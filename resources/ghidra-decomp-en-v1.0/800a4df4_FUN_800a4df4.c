// Function: FUN_800a4df4
// Entry: 800a4df4
// Size: 40540 bytes

/* WARNING: Removing unreachable block (ram,0x800aec28) */
/* WARNING: Removing unreachable block (ram,0x800aec18) */
/* WARNING: Removing unreachable block (ram,0x800aa804) */
/* WARNING: Removing unreachable block (ram,0x800aa844) */
/* WARNING: Removing unreachable block (ram,0x800aa810) */
/* WARNING: Removing unreachable block (ram,0x800aec10) */
/* WARNING: Removing unreachable block (ram,0x800aec20) */
/* WARNING: Removing unreachable block (ram,0x800aec30) */

void FUN_800a4df4(undefined4 param_1,undefined4 param_2,short *param_3,uint param_4,
                 undefined4 param_5,float *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  char cVar4;
  short *psVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  short sVar10;
  undefined4 uVar11;
  undefined8 in_f27;
  double dVar12;
  undefined8 in_f28;
  double dVar13;
  undefined8 in_f29;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  undefined8 uVar17;
  short local_128;
  short local_126;
  short local_124;
  float local_120;
  float local_11c;
  float local_118;
  float local_114;
  short *local_110;
  undefined4 local_10c;
  uint local_108;
  short local_104;
  short local_102;
  short local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  undefined2 local_d0;
  short local_ce;
  undefined *local_cc;
  uint local_c8;
  uint local_c4;
  uint local_c0;
  uint local_bc;
  ushort local_b8;
  ushort local_b6;
  ushort local_b4;
  undefined local_b2;
  undefined local_b0;
  undefined local_af;
  undefined local_ae;
  undefined4 local_a8;
  uint uStack164;
  double local_a0;
  double local_98;
  double local_90;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  double local_78;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
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
  uVar17 = FUN_802860d4();
  psVar5 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar9 = (int)uVar17;
  if (((899 < iVar9) && (iVar9 < 0x3b5)) || ((0x5dc < iVar9 && (iVar9 < 0x641)))) {
    DAT_8039c2e0 = 2000;
    if (DAT_803dd2c8 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2c8 = (int *)FUN_80013ec8(0x1a,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2c8 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((599 < iVar9) && (iVar9 < 700)) {
    DAT_8039c2e2 = 2000;
    if (DAT_803dd2cc == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2cc = (int *)FUN_80013ec8(0x1b,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2cc + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((499 < iVar9) && (iVar9 < 600)) {
    DAT_8039c2e4 = 2000;
    if (DAT_803dd2d0 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2d0 = (int *)FUN_80013ec8(0x1c,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2d0 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((399 < iVar9) && (iVar9 < 500)) {
    DAT_8039c2e6 = 2000;
    if (DAT_803dd2d4 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2d4 = (int *)FUN_80013ec8(0x1d,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2d4 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((199 < iVar9) && (iVar9 < 300)) {
    DAT_8039c2e8 = 2000;
    if (DAT_803dd2d8 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2d8 = (int *)FUN_80013ec8(0x1e,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2d8 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x419 < iVar9) && (iVar9 < 0x44c)) {
    DAT_8039c2ea = 2000;
    if (DAT_803dd2dc == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2dc = (int *)FUN_80013ec8(0x1f,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2dc + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x739 < iVar9) && (iVar9 < 0x76c)) {
    DAT_8039c300 = 2000;
    if (DAT_803dd2e0 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2e0 = (int *)FUN_80013ec8(0x2a,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2e0 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((iVar9 - 0x84U < 2) || ((0x89 < iVar9 && (iVar9 < 200)))) {
    DAT_8039c2ec = 2000;
    if (DAT_803dd2e4 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2e4 = (int *)FUN_80013ec8(0x20,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2e4 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x3b5 < iVar9) && (iVar9 < 0x3de)) {
    DAT_8039c2f0 = 2000;
    if (DAT_803dd2ec == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2ec = (int *)FUN_80013ec8(0x22,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2ec + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x351 < iVar9) && (iVar9 < 900)) {
    DAT_8039c2ee = 2000;
    if (DAT_803dd2e8 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2e8 = (int *)FUN_80013ec8(0x21,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2e8 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x329 < iVar9) && (iVar9 < 0x351)) {
    DAT_8039c2f2 = 2000;
    if (DAT_803dd2f0 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2f0 = (int *)FUN_80013ec8(0x23,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2f0 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((299 < iVar9) && (iVar9 < 400)) {
    DAT_8039c2f4 = 2000;
    if (DAT_803dd2f4 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2f4 = (int *)FUN_80013ec8(0x24,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2f4 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x47d < iVar9) && (iVar9 < 0x4b0)) {
    DAT_8039c2f6 = 2000;
    if (DAT_803dd2f8 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2f8 = (int *)FUN_80013ec8(0x25,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2f8 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x4af < iVar9) && (iVar9 < 0x4e2)) {
    DAT_8039c2f8 = 2000;
    if (DAT_803dd2fc == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd2fc = (int *)FUN_80013ec8(0x27,2);
    }
    uVar6 = (**(code **)(*DAT_803dd2fc + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((999 < iVar9) && (iVar9 < 0x41a)) {
    DAT_8039c2fa = 2000;
    if (DAT_803dd300 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd300 = (int *)FUN_80013ec8(0x28,2);
    }
    uVar6 = (**(code **)(*DAT_803dd300 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((1099 < iVar9) && (iVar9 < 0x47e)) {
    DAT_8039c2fc = 2000;
    if (DAT_803dd304 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd304 = (int *)FUN_80013ec8(0x26,2);
    }
    uVar6 = (**(code **)(*DAT_803dd304 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x6d6 < iVar9) && (iVar9 < 0x708)) {
    DAT_8039c2fe = 2000;
    if (DAT_803dd308 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd308 = (int *)FUN_80013ec8(0x29,2);
    }
    uVar6 = (**(code **)(*DAT_803dd308 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x707 < iVar9) && (iVar9 < 0x73a)) {
    DAT_8039c302 = 2000;
    if (DAT_803dd30c == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd30c = (int *)FUN_80013ec8(0x2b,2);
    }
    uVar6 = (**(code **)(*DAT_803dd30c + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x76b < iVar9) && (iVar9 < 0x79e)) {
    DAT_8039c304 = 2000;
    if (DAT_803dd310 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd310 = (int *)FUN_80013ec8(0x2c,2);
    }
    uVar6 = (**(code **)(*DAT_803dd310 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  if ((0x79d < iVar9) && (iVar9 < 0x834)) {
    DAT_8039c306 = 2000;
    if (DAT_803dd314 == (int *)0x0) {
      DAT_803dd2c0 = DAT_803dd2c0 + '\x01';
      DAT_803dd314 = (int *)FUN_80013ec8(0x2d,2);
    }
    uVar6 = (**(code **)(*DAT_803dd314 + 8))(psVar5,iVar9,param_3,param_4,param_5,param_6);
    goto LAB_800aec10;
  }
  FLOAT_803db7a0 = FLOAT_803db7a0 + FLOAT_803df4c8;
  if (FLOAT_803df4d0 < FLOAT_803db7a0) {
    FLOAT_803db7a0 = FLOAT_803df4cc;
  }
  FLOAT_803db7a4 = FLOAT_803db7a4 + FLOAT_803df4d4;
  if (FLOAT_803df4d0 < FLOAT_803db7a4) {
    FLOAT_803db7a4 = FLOAT_803df4d8;
  }
  if (psVar5 == (short *)0x0) {
    uVar6 = 0xffffffff;
    goto LAB_800aec10;
  }
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (short *)0x0) {
      uVar6 = 0xffffffff;
      goto LAB_800aec10;
    }
    local_f8 = *(float *)(param_3 + 6);
    local_f4 = *(float *)(param_3 + 8);
    local_f0 = *(float *)(param_3 + 10);
    local_fc = *(float *)(param_3 + 4);
    local_100 = param_3[2];
    local_102 = param_3[1];
    local_104 = *param_3;
    local_ae = (undefined)param_5;
  }
  cVar4 = '\0';
  local_cc = (undefined *)0x0;
  local_c8 = 0;
  local_b2 = (undefined)uVar17;
  local_e0 = FLOAT_803df4dc;
  local_dc = FLOAT_803df4dc;
  local_d8 = FLOAT_803df4dc;
  local_ec = FLOAT_803df4dc;
  local_e8 = FLOAT_803df4dc;
  local_e4 = FLOAT_803df4dc;
  local_d4 = FLOAT_803df4dc;
  local_108 = 0;
  local_10c = 0xffffffff;
  local_b0 = 0xff;
  local_af = 0;
  local_ce = 0;
  local_b8 = 0xffff;
  local_b6 = 0xffff;
  local_b4 = 0xffff;
  local_c4 = 0xffff;
  local_c0 = 0xffff;
  local_bc = 0xffff;
  local_d0 = 0;
  local_110 = psVar5;
  if (iVar9 == 0x72) {
    uVar7 = FUN_800221a0(1,4);
    local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
    local_d4 = FLOAT_803df618 * (float)(local_78 - DOUBLE_803df710);
    local_108 = FUN_800221a0(0x1e,0x3c);
    local_cc = (undefined *)0x80100;
    local_c8 = 0x4000802;
    local_af = 0;
    local_ce = 0xde;
    local_b0 = FUN_800221a0(0x96,0xfa);
  }
  else if (iVar9 < 0x72) {
    if (iVar9 == 0x34) {
      local_d4 = FLOAT_803df608;
      local_108 = 0x1e;
      local_af = 0x20;
      local_cc = (undefined *)0x400210;
      local_ce = 0x71;
    }
    else if (iVar9 < 0x34) {
      if (iVar9 == 0x1b) {
        uVar7 = FUN_800221a0(0,0x3c);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e8 = FLOAT_803df4f0 * (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0,4);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_d4 = FLOAT_803df690 *
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        iVar8 = FUN_800221a0(0,3);
        uStack132 = iVar8 + 1U ^ 0x80000000;
        local_88 = 0x43300000;
        local_108 = (uint)(FLOAT_803df6a0 *
                          (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710));
        local_90 = (double)(longlong)(int)local_108;
        local_af = 5;
        local_cc = (undefined *)0x1000211;
        local_ce = 0x30;
      }
      else if (iVar9 < 0x1b) {
        if (iVar9 == 0xb) goto LAB_800aeb28;
        if (iVar9 < 0xb) {
          if (iVar9 == 5) {
            if (param_3 == (short *)0x0) {
              uVar6 = 0xffffffff;
              goto LAB_800aec10;
            }
            uVar7 = FUN_800221a0(0xffffffe2,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803df5d8 * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xffffffe2,0x1e);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_dc = FLOAT_803df5d8 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0xffffffe2,0x1e);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_d8 = FLOAT_803df5d8 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            uVar7 = FUN_800221a0(0xf,0x23);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e8 = FLOAT_803df4e4 * (float)(local_90 - DOUBLE_803df710);
            uVar7 = FUN_800221a0(100,0x96);
            local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df5dc * (float)(local_98 - DOUBLE_803df710);
            local_108 = FUN_800221a0(0x32,0x50);
            local_af = FUN_800221a0(10,0x1e);
            local_cc = (undefined *)0x100218;
            local_c8 = 0x4000000;
            local_ce = param_3[2];
            if (local_ce == 0x4c) {
              local_b8 = 0x6400;
              local_b6 = 0x3200;
              local_b4 = 0xa000;
              local_c4 = 500;
              local_c0 = 0;
              local_bc = 1000;
              local_c8 = 0x4000020;
            }
          }
          else if (iVar9 < 5) {
            if (iVar9 == 2) {
              uVar7 = FUN_800221a0(0xffffffec,0x14);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = FLOAT_803df638 * (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0xffffffec,0x14);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = FLOAT_803df638 *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0xffffffec,0x14);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = FLOAT_803df638 *
                         (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0,0x1e);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df4c8 * (float)(local_90 - DOUBLE_803df710) + FLOAT_803df68c;
              iVar8 = FUN_800221a0(0,8);
              local_108 = iVar8 + 8;
              local_b0 = 0xff;
              local_cc = (undefined *)0x100100;
              local_ce = 0x33;
            }
            else if (iVar9 < 2) {
              if (iVar9 == 0) {
                local_d4 = FLOAT_803df4e8;
                local_108 = 6;
                local_d0 = 0;
                local_cc = (undefined *)0x10;
                local_ce = 0x87;
              }
              else {
                if (iVar9 < 0) goto LAB_800aeb28;
                local_dc = FLOAT_803df5c8;
                uVar7 = FUN_800221a0(0xfffffff1,0xf);
                local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_ec = FLOAT_803df568 * FLOAT_803db7a8 * (float)(local_78 - DOUBLE_803df710);
                uStack124 = FUN_800221a0(5,0x14);
                uStack124 = uStack124 ^ 0x80000000;
                local_80 = 0x43300000;
                local_e8 = FLOAT_803df5b4 *
                           (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
                uStack132 = FUN_800221a0(0xfffffff1,0xf);
                uStack132 = uStack132 ^ 0x80000000;
                local_88 = 0x43300000;
                local_e4 = FLOAT_803df568 * FLOAT_803db7a8 *
                           (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
                uVar7 = FUN_800221a0(0,10);
                local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_d4 = FLOAT_803df524 * (float)(local_90 - DOUBLE_803df710) + FLOAT_803df5b4;
                local_b0 = 0xff;
                local_af = 0xf;
                local_cc = (undefined *)0x588008;
                local_c8 = 0x10000;
                local_ce = 0x23b;
                local_10c = 4;
              }
            }
            else if (iVar9 < 4) {
              if (param_3 == (short *)0x0) {
                uVar6 = 0xffffffff;
                goto LAB_800aec10;
              }
              uVar7 = FUN_800221a0(0x14,0x3c);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_dc = FLOAT_803df4d8 * (float)(local_78 - DOUBLE_803df710);
              local_d4 = FLOAT_803df5d4;
              local_108 = 0x23;
              local_b0 = 0x96;
              local_af = 0x14;
              local_cc = (undefined *)0x9100110;
              local_c8 = 0x4000000;
              local_ce = param_3[2];
            }
            else {
              uVar7 = FUN_800221a0(10,0x14);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803df5cc * (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0,10);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_d4 = FLOAT_803df524 *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710) +
                         FLOAT_803df5d0;
              local_108 = 0x3c;
              local_b0 = 0xcd;
              local_af = 6;
              local_cc = (undefined *)0xa100200;
              local_ce = 0x47;
            }
          }
          else if (iVar9 == 8) {
            local_dc = FLOAT_803df644;
            local_d4 = FLOAT_803df4ec;
            local_108 = 0x30;
            local_b0 = 200;
            local_cc = (undefined *)0x300002;
            local_ce = 0x2c;
          }
          else if (iVar9 < 8) {
            if (iVar9 < 7) {
              local_d4 = FLOAT_803df624;
              local_108 = 0x12;
              local_cc = (undefined *)0x300200;
              local_ce = 0x33;
            }
            else {
              if (param_3 == (short *)0x0) {
                uVar6 = 0xffffffff;
                goto LAB_800aec10;
              }
              uVar7 = FUN_800221a0(0xffffffe2,0x1e);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = FLOAT_803df5d8 * (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0xffffffe2,0x1e);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = FLOAT_803df5d8 *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0xffffffe2,0x1e);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = FLOAT_803df5d8 *
                         (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0xffffffd8,0x28);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803df5e0 * (float)(local_90 - DOUBLE_803df710);
              uVar7 = FUN_800221a0(10,0x28);
              local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803df5e0 * (float)(local_98 - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0xffffffd8,0x28);
              local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803df5e0 * (float)(local_a0 - DOUBLE_803df710);
              local_d4 = FLOAT_803df568;
              local_108 = FUN_800221a0(0x14,0x32);
              local_af = 0x1e;
              local_cc = (undefined *)0x511;
              local_c8 = 0x4000000;
              local_ce = param_3[2];
            }
          }
          else if (iVar9 < 10) {
            local_dc = FLOAT_803df644;
            local_d8 = FLOAT_803df5b8;
            local_d4 = FLOAT_803df4ec;
            local_108 = 0x3c;
            local_b0 = 200;
            local_cc = (undefined *)0x300000;
            local_ce = 0x2c;
          }
          else {
            local_d4 = FLOAT_803df4ec;
            local_108 = 0x3c;
            local_b0 = 200;
            local_cc = (undefined *)0x300000;
            local_ce = 0x2c;
          }
        }
        else if (iVar9 == 0x12) {
          local_dc = FLOAT_803df630;
          local_d4 = FLOAT_803df4e0;
          local_108 = 0x14d;
          local_cc = (undefined *)0x10012;
          local_ce = 0x33;
        }
        else if (iVar9 < 0x12) {
          if (iVar9 == 0xf) {
            local_e0 = FLOAT_803df698;
            local_dc = FLOAT_803df630;
            local_d8 = FLOAT_803df590;
            iVar8 = FUN_800221a0(0,0xa0);
            local_78 = (double)CONCAT44(0x43300000,0x50U - iVar8 ^ 0x80000000);
            local_ec = FLOAT_803df4e4 * (float)(local_78 - DOUBLE_803df710);
            iVar8 = FUN_800221a0(0,0xa0);
            uStack124 = 0x50U - iVar8 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = FLOAT_803df4e4 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            local_d4 = FLOAT_803df4e0;
            iVar8 = FUN_800221a0(0,3);
            uStack132 = iVar8 + 1U ^ 0x80000000;
            local_88 = 0x43300000;
            local_108 = (uint)(FLOAT_803df660 *
                              (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710));
            local_90 = (double)(longlong)(int)local_108;
            local_cc = (undefined *)0x110214;
            local_ce = 0x30;
          }
          else if (iVar9 < 0xf) {
            if (iVar9 == 0xd) {
              local_d4 = FLOAT_803df4f0;
              local_108 = 0x8a;
              local_cc = (undefined *)0x10000;
              local_ce = 0x30;
            }
            else if (iVar9 < 0xd) {
              local_d4 = FLOAT_803df4f0;
              local_108 = 0x8a;
              local_cc = (undefined *)0x10000;
              local_ce = 0x30;
            }
            else {
              local_dc = FLOAT_803df604;
              local_d4 = FLOAT_803df4f0;
              local_108 = 0x8a;
              local_cc = (undefined *)0x10002;
              local_ce = 0x30;
            }
          }
          else if (iVar9 < 0x11) {
            iVar8 = FUN_800221a0(0,0x28);
            local_78 = (double)CONCAT44(0x43300000,0x14U - iVar8 ^ 0x80000000);
            local_dc = (float)(local_78 - DOUBLE_803df710);
            iVar8 = FUN_800221a0(0,0xa0);
            uStack124 = 0x50U - iVar8 ^ 0x80000000;
            local_80 = 0x43300000;
            local_ec = FLOAT_803df4e4 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            iVar8 = FUN_800221a0(0,0xa0);
            uStack132 = 0x50U - iVar8 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803df4e4 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            local_d4 = FLOAT_803df4e0;
            iVar8 = FUN_800221a0(0,3);
            local_90 = (double)CONCAT44(0x43300000,iVar8 + 1U ^ 0x80000000);
            local_108 = (uint)(FLOAT_803df6c4 * (float)(local_90 - DOUBLE_803df710));
            local_98 = (double)(longlong)(int)local_108;
            local_cc = (undefined *)0x110204;
            local_ce = 0x30;
          }
          else {
            iVar8 = FUN_800221a0(0,0xa0);
            local_78 = (double)CONCAT44(0x43300000,0x50U - iVar8 ^ 0x80000000);
            local_ec = FLOAT_803df4e4 * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0,0x50);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803df608 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            iVar8 = FUN_800221a0(0,0xa0);
            uStack132 = 0x50U - iVar8 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803df4e4 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            local_d4 = FLOAT_803df4e0;
            iVar8 = FUN_800221a0(0,3);
            local_90 = (double)CONCAT44(0x43300000,iVar8 + 1U ^ 0x80000000);
            local_108 = (uint)(FLOAT_803df660 * (float)(local_90 - DOUBLE_803df710));
            local_98 = (double)(longlong)(int)local_108;
            local_cc = (undefined *)0x1110214;
            local_ce = 0x33;
          }
        }
        else if (iVar9 == 0x19) {
          uVar7 = FUN_800221a0(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803df4e8 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffff6,10);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = FLOAT_803df4e8 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xfffffff6,10);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = FLOAT_803df4e8 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          local_d4 = FLOAT_803df4c8;
          local_108 = 0x32;
          local_cc = (undefined *)0x211;
          local_ce = 0x30;
        }
        else if (iVar9 < 0x19) {
          if (iVar9 == 0x14) {
            local_d4 = FLOAT_803df530;
            local_108 = 0xd;
            local_cc = (undefined *)0x110212;
            local_ce = 0x33;
          }
          else {
            if (0x13 < iVar9) goto LAB_800aeb28;
            local_d4 = FLOAT_803df6c0;
            local_108 = 0xd05;
            local_b0 = 0;
            local_cc = (undefined *)0x11;
            local_ce = 0x30;
          }
        }
        else {
          iVar8 = FUN_800221a0(0,0x14);
          local_78 = (double)CONCAT44(0x43300000,10U - iVar8 ^ 0x80000000);
          local_ec = FLOAT_803df4f0 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0,0x3c);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = FLOAT_803df4f0 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,0x14);
          uStack132 = 10U - iVar8 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = FLOAT_803df4f0 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0,4);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df690 * (float)(local_90 - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,3);
          local_98 = (double)CONCAT44(0x43300000,iVar8 + 1U ^ 0x80000000);
          local_108 = (uint)(FLOAT_803df69c * (float)(local_98 - DOUBLE_803df710));
          local_a0 = (double)(longlong)(int)local_108;
          local_cc = (undefined *)0x1000211;
          local_ce = 0x30;
        }
      }
      else if (iVar9 == 0x28) {
        local_d4 = FLOAT_803df4cc;
        local_108 = 0x46;
        local_cc = (undefined *)0xb100200;
        local_ce = 0x74;
      }
      else if (iVar9 < 0x28) {
        if (iVar9 == 0x22) {
          local_d8 = FLOAT_803df4fc;
          local_d4 = FLOAT_803df4c8;
          local_108 = 0x178e;
          local_b0 = 0xff;
          local_af = 0x10;
          local_cc = (undefined *)0x14;
          local_ce = 0x30;
        }
        else if (iVar9 < 0x22) {
          if (iVar9 == 0x1f) {
            uVar7 = FUN_800221a0(2,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df4f0 * (float)(local_78 - DOUBLE_803df710);
            local_108 = 200;
            local_cc = (undefined *)0xa100201;
            local_ce = 0x56;
          }
          else if (iVar9 < 0x1f) {
            if (iVar9 == 0x1d) {
              local_dc = FLOAT_803df6b4;
              local_d8 = FLOAT_803df6b8;
              iVar8 = FUN_800221a0(0,0x14);
              local_78 = (double)CONCAT44(0x43300000,10U - iVar8 ^ 0x80000000);
              local_ec = FLOAT_803df68c * (float)(local_78 - DOUBLE_803df710);
              iVar8 = FUN_800221a0(0,0x14);
              uStack124 = 10U - iVar8 ^ 0x80000000;
              local_80 = 0x43300000;
              local_e8 = FLOAT_803df68c *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              local_d4 = FLOAT_803df6bc;
              local_108 = 0x78;
              local_cc = (undefined *)0x204;
              local_ce = 0x1f0;
            }
            else if (iVar9 < 0x1d) {
              uVar7 = FUN_800221a0(0xffffff38,200);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803df710);
              local_dc = FLOAT_803df6ac;
              uStack124 = FUN_800221a0(0xffffff38,200);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              iVar8 = FUN_800221a0(0,0x14);
              uStack132 = 10U - iVar8 ^ 0x80000000;
              local_88 = 0x43300000;
              local_ec = FLOAT_803df4ec *
                         (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              iVar8 = FUN_800221a0(0,0x14);
              local_90 = (double)CONCAT44(0x43300000,10U - iVar8 ^ 0x80000000);
              local_e4 = FLOAT_803df4ec * (float)(local_90 - DOUBLE_803df710);
              iVar8 = FUN_800221a0(0,0x14);
              local_98 = (double)CONCAT44(0x43300000,10U - iVar8 ^ 0x80000000);
              local_e8 = FLOAT_803df68c * (float)(local_98 - DOUBLE_803df710);
              local_d4 = FLOAT_803df6b0;
              local_108 = 0x104;
              local_cc = (undefined *)0x1000202;
              local_10c = 0x1e;
              local_e0 = FLOAT_803df4dc;
              local_dc = FLOAT_803df540;
              local_d8 = FLOAT_803df4dc;
              iVar8 = FUN_800221a0(0,0x14);
              local_a0 = (double)CONCAT44(0x43300000,10U - iVar8 ^ 0x80000000);
              local_e4 = FLOAT_803df4ec * (float)(local_a0 - DOUBLE_803df710);
              local_d4 = FLOAT_803df600;
              local_108 = 0xa0;
              local_cc = (undefined *)0x11000204;
              local_ce = 0x151;
            }
            else {
              uVar7 = FUN_800221a0(1,4);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df5b4 * (float)(local_78 - DOUBLE_803df710);
              local_108 = 0x5a;
              local_b0 = 0xff;
              local_cc = (undefined *)0xa100100;
              local_ce = 0x56;
              local_af = 0;
            }
          }
          else if (iVar9 < 0x21) {
            local_dc = FLOAT_803df5b8;
            local_d4 = FLOAT_803df62c;
            local_108 = 200;
            local_b0 = 0x9b;
            local_cc = (undefined *)0x12;
            local_ce = 0x22d;
          }
          else {
            iVar8 = FUN_800221a0(0,0x14);
            local_78 = (double)CONCAT44(0x43300000,10U - iVar8 ^ 0x80000000);
            local_e0 = (float)(local_78 - DOUBLE_803df710);
            iVar8 = FUN_800221a0(0,0x14);
            uStack124 = 10U - iVar8 ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            local_ec = FLOAT_803df628;
            local_e8 = FLOAT_803df6a4;
            local_e4 = FLOAT_803df628;
            local_d4 = FLOAT_803df62c;
            local_108 = 0x32;
            local_cc = (undefined *)0x201;
            local_ce = 0x321;
          }
        }
        else if (iVar9 == 0x25) {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          if (param_3 == (short *)0x0) {
            uVar6 = 0xffffffff;
            goto LAB_800aec10;
          }
          uVar7 = FUN_800221a0(0,6);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = *(float *)(param_3 + 6) + (float)(local_78 - DOUBLE_803df710);
          local_dc = *(float *)(param_3 + 8);
          uStack124 = FUN_800221a0(0,6);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = *(float *)(param_3 + 10) +
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0,10);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803df634 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(4,8);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df5b4 * (float)(local_90 - DOUBLE_803df710);
          local_108 = 0x24;
          local_b0 = 0x41;
          local_cc = (undefined *)0x100112;
          local_ce = 0x61;
        }
        else if (iVar9 < 0x25) {
          if (iVar9 < 0x24) {
            local_dc = FLOAT_803df580;
            local_d4 = FLOAT_803df6a8;
            local_108 = 0x69;
            local_cc = (undefined *)0x400010;
            local_ce = 0x4b;
          }
          else {
            local_d4 = FLOAT_803df6a8;
            local_108 = 0x5f;
            local_cc = (undefined *)0x400212;
            local_ce = 0x4b;
          }
        }
        else if (iVar9 < 0x27) {
          uVar7 = FUN_800221a0(0xffffffff,1);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803df710);
          if (param_6 != (float *)0x0) {
            local_e0 = local_e0 + param_6[1];
          }
          local_dc = FLOAT_803df4dc;
          uVar7 = FUN_800221a0(0xffffffff,1);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = (float)(local_78 - DOUBLE_803df710);
          local_e8 = FLOAT_803df608;
          local_d4 = FLOAT_803df4e0;
          if (param_6 == (float *)0x0) {
            local_108 = 0x78;
          }
          else {
            local_108 = (uint)*param_6;
            local_78 = (double)(longlong)(int)local_108;
          }
          local_af = 0;
          local_cc = (undefined *)0x100201;
          local_ce = 99;
          local_11c = FLOAT_803df4dc;
          local_118 = FLOAT_803df4dc;
          local_114 = FLOAT_803df4dc;
          local_120 = FLOAT_803df4d0;
          local_124 = 0;
          local_126 = 0;
          local_128 = *psVar5;
          FUN_80021ac8(&local_128,&local_e0);
        }
        else {
          local_dc = FLOAT_803df580;
          uVar7 = FUN_800221a0(1,2);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df624 * (float)(local_78 - DOUBLE_803df710);
          local_108 = 200;
          local_cc = (undefined *)0xa100201;
          local_ce = 0x6b;
        }
      }
      else if (iVar9 == 0x2e) {
        local_d4 = FLOAT_803df4cc;
        local_108 = 0x30;
        local_af = 0;
        local_cc = (undefined *)0x8100210;
        local_ce = 0x5e;
      }
      else if (iVar9 < 0x2e) {
        if (iVar9 == 0x2b) {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
          }
          local_ec = FLOAT_803df608;
          uVar7 = FUN_800221a0(0,0xfffe);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          dVar12 = (double)(float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0,0xfffe);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          dVar13 = (double)(float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0,0xfffe);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_11c = FLOAT_803df4dc;
          local_118 = FLOAT_803df4dc;
          local_114 = FLOAT_803df4dc;
          local_120 = FLOAT_803df4d0;
          iVar8 = (int)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          local_90 = (double)(longlong)iVar8;
          local_124 = (short)iVar8;
          local_98 = (double)(longlong)(int)dVar13;
          local_126 = (short)(int)dVar13;
          local_a0 = (double)(longlong)(int)dVar12;
          local_128 = (short)(int)dVar12;
          FUN_80021ac8(&local_128,&local_ec);
          local_d4 = FLOAT_803df690;
          local_108 = 0x32;
          local_d0 = 0;
          local_cc = (undefined *)0x100;
          local_ce = 0x30;
        }
        else if (iVar9 < 0x2b) {
          if (iVar9 < 0x2a) goto LAB_800aeb28;
          uVar7 = FUN_800221a0(0xffffffe2,0x1e);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df4cc * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xffffffe2,0x1e);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803df4cc *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xffffffe2,0x1e);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803df4cc *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0,10);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df4d4 * (float)(local_90 - DOUBLE_803df710) + FLOAT_803df62c;
          local_108 = FUN_800221a0(0x14,0x32);
          local_b0 = 0x9b;
          local_af = 0xe;
          local_cc = (undefined *)0x100110;
          if (param_6 == (float *)0x0) {
            local_ce = 0x88;
          }
          else {
            local_ce = 0x78;
          }
        }
        else if (iVar9 < 0x2d) {
          local_d4 = FLOAT_803df4e8;
          local_108 = 10;
          local_af = 0;
          local_cc = (undefined *)0x80211;
          local_ce = 0x3ff;
        }
        else {
          local_dc = FLOAT_803df644;
          iVar8 = FUN_800221a0(0,0xa0);
          local_78 = (double)CONCAT44(0x43300000,0x50U - iVar8 ^ 0x80000000);
          local_ec = FLOAT_803df4e8 * (float)(local_78 - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,0xa0);
          uStack124 = 0x50U - iVar8 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e4 = FLOAT_803df4e8 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          local_d4 = FLOAT_803df600;
          uStack132 = FUN_800221a0(1,4);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_108 = (uint)(FLOAT_803df660 *
                            (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710));
          local_90 = (double)(longlong)(int)local_108;
          local_cc = (undefined *)0x100000;
          local_ce = 0x30;
        }
      }
      else if (iVar9 == 0x31) {
        local_d4 = FLOAT_803df694;
        local_108 = 0x46;
        local_af = 0;
        local_cc = (undefined *)0xb100200;
        local_ce = 0x74;
      }
      else if (iVar9 < 0x31) {
        if (iVar9 < 0x30) {
          local_d4 = FLOAT_803df608;
          local_108 = 0x32;
          local_af = 0x20;
          local_cc = (undefined *)0x400010;
          local_ce = 0x71;
        }
        else {
          local_d4 = FLOAT_803df4d0;
          local_108 = 0x14;
          local_cc = (undefined *)0x400010;
          local_ce = 0x7c;
        }
      }
      else if (iVar9 < 0x33) {
        local_d4 = FLOAT_803df5e0;
        local_108 = 0x96;
        local_cc = (undefined *)0x400012;
        local_ce = 0x7c;
      }
      else {
        local_dc = FLOAT_803df644;
        local_d4 = FLOAT_803df62c;
        local_108 = 0x55;
        local_cc = (undefined *)0x400012;
        local_ce = 0x7c;
      }
    }
    else if (iVar9 == 0x51) {
      local_d4 = FLOAT_803df4c8;
      local_108 = 10;
      local_cc = (undefined *)0x200;
      local_ce = 0x2b;
    }
    else if (iVar9 < 0x51) {
      if (iVar9 == 0x42) {
        uVar7 = FUN_800221a0(0,4);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = FLOAT_803df4f8 - (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0,4);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = FLOAT_803df4f8 -
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        uStack132 = FUN_800221a0(0,4);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = FLOAT_803df4f8 -
                   (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
        local_d4 = FLOAT_803df568;
        local_108 = 1;
        local_cc = (undefined *)0x70800;
        local_ce = FUN_800221a0(0,1);
        local_ce = local_ce + 0xdd;
        local_f8 = FLOAT_803df4dc;
        local_f4 = FLOAT_803df4dc;
        local_f0 = FLOAT_803df4dc;
        local_fc = FLOAT_803df4d0;
        local_100 = FUN_800221a0(0,1000);
        local_100 = 500 - local_100;
        local_102 = FUN_800221a0(0,1000);
        local_102 = 500 - local_102;
        local_104 = FUN_800221a0(0,1000);
        local_104 = 500 - local_104;
      }
      else if (iVar9 < 0x42) {
        if (iVar9 == 0x3a) {
          iVar8 = FUN_800221a0(0,0x3c);
          local_78 = (double)CONCAT44(0x43300000,0x1eU - iVar8 ^ 0x80000000);
          local_e0 = FLOAT_803df664 * (float)(local_78 - DOUBLE_803df710);
          local_dc = FLOAT_803df580;
          iVar8 = FUN_800221a0(0,0x3c);
          uStack124 = 0x1eU - iVar8 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803df664 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0x28,0x50);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803df66c *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df670 * (float)(local_90 - DOUBLE_803df710);
          local_108 = 0xb4;
          local_af = 0;
          local_cc = (undefined *)0x80400200;
          local_ce = 0x47;
        }
        else if (iVar9 < 0x3a) {
          if (iVar9 == 0x37) {
            local_d4 = FLOAT_803df4e4;
            local_108 = 0x14;
            local_d0 = 0x9a;
            local_cc = (undefined *)0x100210;
            local_ce = 0x87;
          }
          else if (iVar9 < 0x37) {
            if (iVar9 < 0x36) {
              iVar8 = FUN_800221a0(0,0x3c);
              local_78 = (double)CONCAT44(0x43300000,0x1eU - iVar8 ^ 0x80000000);
              local_e0 = FLOAT_803df664 * (float)(local_78 - DOUBLE_803df710);
              local_dc = FLOAT_803df668;
              iVar8 = FUN_800221a0(0,0x3c);
              uStack124 = 0x1eU - iVar8 ^ 0x80000000;
              local_80 = 0x43300000;
              local_d8 = FLOAT_803df664 *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0x28,0x50);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e8 = FLOAT_803df66c *
                         (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0x28,0x50);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df670 * (float)(local_90 - DOUBLE_803df710);
              local_108 = FUN_800221a0(0x28,0x50);
              local_af = 0;
              local_cc = (undefined *)0x80400001;
              local_ce = 0x47;
            }
            else {
              if (param_6 == (float *)0x0) {
                uVar6 = 0xffffffff;
                goto LAB_800aec10;
              }
              local_d4 = FLOAT_803df568;
              local_108 = 0x20;
              local_b0 = 0xff;
              local_af = 0x20;
              local_cc = (undefined *)0x1100201;
              local_ce = 0x249;
            }
          }
          else if (iVar9 < 0x39) {
            FUN_80292de4(0x4233d);
            dVar13 = (double)FLOAT_803df644;
            dVar14 = (double)FLOAT_803df4e8;
            dVar15 = (double)FLOAT_803df600;
            dVar16 = (double)FLOAT_803df660;
            dVar12 = DOUBLE_803df710;
            for (sVar10 = 0; sVar10 < 0x28; sVar10 = sVar10 + 1) {
              local_dc = (float)dVar13;
              iVar8 = FUN_800221a0(0,0xa0);
              local_78 = (double)CONCAT44(0x43300000,0x50U - iVar8 ^ 0x80000000);
              local_ec = (float)(dVar14 * (double)(float)(local_78 - dVar12));
              iVar8 = FUN_800221a0(0,0xa0);
              uStack124 = 0x50U - iVar8 ^ 0x80000000;
              local_80 = 0x43300000;
              local_e4 = (float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack124) -
                                                         dVar12));
              local_d4 = (float)dVar15;
              uStack132 = FUN_800221a0(1,4);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_108 = (uint)(dVar16 * (double)(float)((double)CONCAT44(0x43300000,uStack132) -
                                                         dVar12));
              local_90 = (double)(longlong)(int)local_108;
              local_cc = (undefined *)0x100011;
              local_ce = 0x30;
              fVar1 = local_f8;
              fVar2 = local_f4;
              fVar3 = local_f0;
              if (local_110 != (short *)0x0) {
                fVar1 = *(float *)(local_110 + 6);
                fVar2 = *(float *)(local_110 + 8);
                fVar3 = *(float *)(local_110 + 10);
              }
              local_d8 = local_d8 + fVar3;
              local_dc = local_dc + fVar2;
              local_e0 = local_e0 + fVar1;
              (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
            }
          }
          else {
            iVar8 = FUN_800221a0(0,1);
            if (iVar8 == 0) {
              local_d8 = FLOAT_803df67c;
            }
            else {
              local_d8 = FLOAT_803df55c;
            }
            uVar7 = FUN_800221a0(1,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df680 * (float)(local_78 - DOUBLE_803df710);
            iVar8 = FUN_800221a0(0,0x18);
            local_108 = iVar8 + 0x18;
            local_b0 = 0xff;
            local_cc = (undefined *)0x100;
            local_ce = 0x33;
          }
        }
        else if (iVar9 == 0x40) {
          uVar7 = FUN_800221a0(0,0x28);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_dc = (float)(local_78 - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,2);
          uStack124 = 1U - iVar8 ^ 0x80000000;
          local_80 = 0x43300000;
          local_ec = FLOAT_803df638 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(1,3);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803df638 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,2);
          local_90 = (double)CONCAT44(0x43300000,1U - iVar8 ^ 0x80000000);
          local_e4 = FLOAT_803df638 * (float)(local_90 - DOUBLE_803df710);
          local_d4 = FLOAT_803df5cc;
          local_108 = 0x96;
          local_cc = (undefined *)0x108;
          local_ce = 0x5c;
        }
        else if (iVar9 < 0x40) {
          if (iVar9 == 0x3c) {
            local_dc = FLOAT_803df5b0;
            uVar7 = FUN_800221a0(1,10);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df5b4 * (float)(local_78 - DOUBLE_803df710) + FLOAT_803df550;
            local_b0 = 0xff;
            local_104 = FUN_800221a0(0,0xffff);
            local_102 = FUN_800221a0(0,0xffff);
            local_104 = FUN_800221a0(0,0xffff);
            local_f8 = FLOAT_803df4dc;
            local_f4 = FLOAT_803df4dc;
            local_f0 = FLOAT_803df4dc;
            iVar8 = FUN_800221a0(0,0x14);
            local_108 = iVar8 + 0x28;
            local_af = 0x10;
            local_cc = (undefined *)0x6100214;
            local_ce = 0xc79;
          }
          else {
            if (0x3b < iVar9) goto LAB_800aa8ac;
            iVar8 = FUN_800221a0(0,0x3c);
            local_78 = (double)CONCAT44(0x43300000,0x1eU - iVar8 ^ 0x80000000);
            local_e0 = FLOAT_803df624 * (float)(local_78 - DOUBLE_803df710);
            local_dc = FLOAT_803df604;
            iVar8 = FUN_800221a0(0,0x3c);
            uStack124 = 0x1eU - iVar8 ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = FLOAT_803df624 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0x28,0x50);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e8 = FLOAT_803df66c *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            uVar7 = FUN_800221a0(0x28,0x50);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df670 * (float)(local_90 - DOUBLE_803df710);
            local_108 = 0x78;
            local_af = 0;
            local_cc = (undefined *)0x80400201;
            local_ce = 0x47;
          }
        }
        else {
          dVar16 = (double)FLOAT_803df63c;
          dVar15 = (double)FLOAT_803df640;
          dVar14 = (double)FLOAT_803df638;
          dVar13 = (double)FLOAT_803df5b4;
          dVar12 = DOUBLE_803df710;
          for (sVar10 = 0; sVar10 < 0x1e; sVar10 = sVar10 + 1) {
            local_dc = (float)dVar16;
            iVar8 = FUN_800221a0(0,4);
            local_78 = (double)CONCAT44(0x43300000,2U - iVar8 ^ 0x80000000);
            local_ec = (float)(dVar15 * (double)(float)(local_78 - dVar12));
            uStack124 = FUN_800221a0(1,2);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = (float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack124) -
                                                       dVar12));
            iVar8 = FUN_800221a0(0,4);
            uStack132 = 2U - iVar8 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack132) -
                                                       dVar12));
            local_d4 = (float)dVar13;
            local_108 = 0x3c;
            local_cc = (undefined *)0x108;
            local_ce = 0x5c;
            (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
          }
        }
      }
      else if (iVar9 == 0x4b) {
        local_d4 = FLOAT_803df5ac;
        local_108 = 0x14;
        local_af = 0;
        local_cc = (undefined *)0x80100;
        local_ce = 0xdf;
      }
      else if (iVar9 < 0x4b) {
        if (iVar9 == 0x48) {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
          }
          uVar7 = FUN_800221a0(1,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e8 = FLOAT_803df508 * (float)(local_78 - DOUBLE_803df710);
          local_11c = FLOAT_803df4dc;
          local_118 = FLOAT_803df4dc;
          local_114 = FLOAT_803df4dc;
          local_120 = FLOAT_803df530;
          local_124 = FUN_800221a0(0,4000);
          local_124 = 2000 - local_124;
          local_126 = FUN_800221a0(0,4000);
          local_126 = 2000 - local_126;
          local_128 = FUN_800221a0(0,4000);
          local_128 = 2000 - local_128;
          FUN_80021ac8(&local_128,&local_ec);
          local_d4 = FLOAT_803df65c;
          local_108 = 0x50;
          local_af = 8;
          local_cc = (undefined *)0x100;
          local_ce = 0xdd;
        }
        else if (iVar9 < 0x48) {
          if (iVar9 < 0x47) {
            if (iVar9 < 0x45) goto LAB_800aa8ac;
            goto LAB_800aeb28;
          }
          uVar7 = FUN_800221a0(0,4);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df4f8 - (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0,4);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803df4f8 -
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0,4);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803df4f8 -
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          local_d4 = FLOAT_803df504;
          local_108 = FUN_800221a0(4,0xe);
          local_cc = (undefined *)0x110100;
          local_ce = 0xc22;
        }
        else if (iVar9 < 0x4a) {
          local_dc = FLOAT_803df604;
          local_d4 = FLOAT_803df530;
          local_108 = 0xe;
          local_b0 = 0;
          local_cc = (undefined *)0x110210;
          local_ce = 0x31;
        }
        else {
          local_dc = FLOAT_803df630;
          local_d4 = FLOAT_803df634;
          local_108 = 0x78;
          local_af = 0;
          local_10c = 0x4b;
          local_cc = (undefined *)0x70000;
          local_ce = FUN_800221a0(0,3);
          local_ce = local_ce + 0xdd;
          local_f8 = FLOAT_803df4dc;
          local_f4 = FLOAT_803df4fc;
          local_f0 = FLOAT_803df4dc;
          local_fc = FLOAT_803df4d0;
          local_100 = 0;
          local_102 = FUN_800221a0(0,1000);
          local_102 = 500 - local_102;
          local_104 = FUN_800221a0(0,1000);
          local_104 = 500 - local_104;
        }
      }
      else if (iVar9 == 0x4e) {
        iVar8 = FUN_800221a0(0,2);
        local_78 = (double)CONCAT44(0x43300000,1U - iVar8 ^ 0x80000000);
        local_ec = FLOAT_803df628 * (float)(local_78 - DOUBLE_803df710);
        iVar8 = FUN_800221a0(0,2);
        uStack124 = 1U - iVar8 ^ 0x80000000;
        local_80 = 0x43300000;
        local_e4 = FLOAT_803df628 *
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        local_d4 = FLOAT_803df62c;
        local_108 = 0x4b;
        local_af = 0;
        local_cc = (undefined *)0x200;
        local_ce = 0x7b;
      }
      else if (iVar9 < 0x4e) {
        if (iVar9 < 0x4d) goto LAB_800aeb28;
        local_dc = FLOAT_803df620;
        local_d4 = FLOAT_803df624;
        local_108 = 400;
        local_af = 0;
        local_10c = 0x4e;
        local_cc = (undefined *)0x20100;
        local_ce = 0xdf;
        local_f8 = FLOAT_803df4dc;
        local_f4 = FLOAT_803df4dc;
        local_f0 = FLOAT_803df4dc;
        local_fc = FLOAT_803df4d0;
        local_100 = FUN_800221a0(0,200);
        local_100 = 100 - local_100;
        local_102 = FUN_800221a0(0,200);
        local_102 = 100 - local_102;
        local_104 = FUN_800221a0(0,200);
        local_104 = 100 - local_104;
      }
      else if (iVar9 < 0x50) {
LAB_800aa8ac:
        local_cc = (undefined *)0x20100100;
        local_108 = 400;
        if (iVar9 == 0x3d) {
          uVar7 = FUN_800221a0(0,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df580 - (float)(local_78 - DOUBLE_803df710);
          local_dc = FLOAT_803df644;
          uStack124 = FUN_800221a0(0,0x14);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803df580 -
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(1,3);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d4 = FLOAT_803df4ec *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          local_c8 = local_c8 | 0x1000000;
        }
        else if (iVar9 == 0x3e) {
          uVar7 = FUN_800221a0(0,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df580 - (float)(local_78 - DOUBLE_803df710);
          local_dc = FLOAT_803df648;
          uStack124 = FUN_800221a0(0,0x14);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803df580 -
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(1,3);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d4 = FLOAT_803df624 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          local_c8 = local_c8 | 0x1000000;
        }
        else if (iVar9 == 0x3f) {
          local_dc = FLOAT_803df64c;
          local_108 = 100;
          uVar7 = FUN_800221a0(1,3);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df624 * (float)(local_78 - DOUBLE_803df710);
          local_c8 = local_c8 | 0x1000000;
        }
        else if (iVar9 == 0x43) {
          local_e0 = FLOAT_803df650;
          local_dc = FLOAT_803df538;
          uVar7 = FUN_800221a0(0,0x78);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = FLOAT_803df564 + (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(1,8);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d4 = FLOAT_803df4e8 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          local_cc = (undefined *)((uint)local_cc | 8);
          local_c8 = local_c8 | 0x1000000;
        }
        else if (iVar9 == 0x44) {
          local_e0 = FLOAT_803df650;
          local_dc = FLOAT_803df654;
          uVar7 = FUN_800221a0(0,0x78);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = (float)(local_78 - DOUBLE_803df710);
          local_e8 = FLOAT_803df658;
          uStack124 = FUN_800221a0(1,8);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d4 = FLOAT_803df4e8 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          local_c8 = local_c8 | 0x1000000;
        }
        local_af = 0x20;
        local_ce = 0x5f;
        local_cc = (undefined *)((uint)local_cc | param_4);
        if (((uint)local_cc & 1) != 0) {
          if (local_110 == (short *)0x0) {
            local_e0 = local_e0 + local_f8;
            local_dc = local_dc + local_f4;
            local_d8 = local_d8 + local_f0;
          }
          else {
            local_e0 = local_e0 + *(float *)(local_110 + 0xc);
            local_dc = local_dc + *(float *)(local_110 + 0xe);
            local_d8 = local_d8 + *(float *)(local_110 + 0x10);
          }
        }
        if ((iVar9 == 0x3e) || (iVar9 == 0x3f)) {
          local_cc = (undefined *)((uint)local_cc | 0x8000000);
        }
      }
      else {
        local_d4 = FLOAT_803df5cc;
        local_108 = 10;
        local_cc = (undefined *)0x200;
        local_ce = 0x2b;
      }
    }
    else if (iVar9 == 0x60) {
      uStack164 = FUN_800221a0(0xfffffff6,10);
      uStack164 = uStack164 ^ 0x80000000;
      local_a8 = 0x43300000;
      local_e0 = (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xfffffff6,10);
      local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_dc = (float)(local_a0 - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xfffffff6,10);
      local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_d8 = (float)(local_98 - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xffffffce,0x32);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_ec = FLOAT_803df4e4 * (float)(local_90 - DOUBLE_803df710);
      uStack132 = FUN_800221a0(0xffffffce,0x32);
      uStack132 = uStack132 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e8 = FLOAT_803df4e4 * (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
      uStack124 = FUN_800221a0(0xffffffce,0x32);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      local_e4 = FLOAT_803df4e4 * (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0x32,100);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_d4 = FLOAT_803df4c8 * (float)(local_78 - DOUBLE_803df710);
      local_cc = (undefined *)0x80180202;
      local_ce = 0x60;
      if (param_6 == (float *)0x0) {
        local_b8 = 0x2000;
        local_b6 = 0x2000;
        local_b4 = 0x2000;
        local_108 = 0x78;
      }
      else {
        local_b8 = *(ushort *)param_6;
        local_b6 = *(ushort *)((int)param_6 + 2);
        local_b4 = *(ushort *)(param_6 + 1);
        local_108 = (uint)*(ushort *)((int)param_6 + 6);
      }
      local_c4 = (uint)local_b8;
      local_c0 = (uint)local_b6;
      local_bc = (uint)local_b4;
      local_b0 = 0x7f;
      local_c8 = 0x4080020;
    }
    else if (iVar9 < 0x60) {
      if (iVar9 == 0x57) {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
          param_3 = &DAT_8039c308;
        }
        uVar7 = FUN_800221a0(0,10);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_dc = (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0xffffff9c,100);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_ec = *(float *)(param_3 + 4) *
                   FLOAT_803df5b4 *
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        uStack132 = FUN_800221a0(200,400);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        local_e8 = *(float *)(param_3 + 4) *
                   FLOAT_803df5b4 *
                   (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
        uVar7 = FUN_800221a0(0xffffff9c,100);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e4 = *(float *)(param_3 + 4) * FLOAT_803df5b4 * (float)(local_90 - DOUBLE_803df710);
        uVar7 = FUN_800221a0(8,0xb);
        local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = *(float *)(param_3 + 4) * FLOAT_803df524 * (float)(local_98 - DOUBLE_803df710);
        local_b0 = 0xbe;
        local_108 = (uint)(FLOAT_803df6c8 * *(float *)(param_3 + 4));
        local_a0 = (double)(longlong)(int)local_108;
        local_cc = (undefined *)0x1200000;
        local_c8 = 0x1000000;
        local_ce = 0x77;
        if (param_6 != (float *)0x0) {
          local_c4 = (uint)*(byte *)param_6 << 8;
          local_b8 = (ushort)local_c4;
          local_c0 = (uint)*(byte *)((int)param_6 + 1) << 8;
          local_b6 = (ushort)local_c0;
          local_bc = (uint)*(byte *)((int)param_6 + 2) << 8;
          local_b4 = (ushort)local_bc;
          local_c8 = 0x1000020;
        }
      }
      else if (iVar9 < 0x57) {
        if (iVar9 == 0x54) {
          iVar8 = FUN_800221a0(0,10);
          local_78 = (double)CONCAT44(0x43300000,5U - iVar8 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,10);
          uStack124 = 5U - iVar8 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(2,0xc);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d4 = FLOAT_803df5cc *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          local_108 = 0x78;
          local_cc = (undefined *)0xa100201;
          local_ce = 0x56;
        }
        else if (iVar9 < 0x54) {
          if (iVar9 < 0x53) goto LAB_800aeb28;
          iVar8 = FUN_800221a0(0,0x3c);
          local_78 = (double)CONCAT44(0x43300000,0x1eU - iVar8 ^ 0x80000000);
          local_e0 = FLOAT_803df664 * (float)(local_78 - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,0x3c);
          uStack124 = 0x1eU - iVar8 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803df664 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0x28,0x50);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803df514 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df670 * (float)(local_90 - DOUBLE_803df710);
          local_108 = 0xd2;
          local_cc = &DAT_80000201;
          local_ce = FUN_800221a0(0,3);
          local_ce = local_ce + 0xdd;
        }
        else if (iVar9 < 0x56) {
          local_d4 = FLOAT_803df4e8;
          local_108 = 0x78;
          local_b0 = 0xff;
          local_af = 0x20;
          local_cc = (undefined *)0xa100201;
          local_ce = 0x56;
        }
        else {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          uVar7 = FUN_800221a0(0xfffffffa,6);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffffa,6);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xfffffffe,2);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_ec = *(float *)(param_3 + 4) *
                     FLOAT_803df508 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0,4);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e8 = *(float *)(param_3 + 4) * FLOAT_803df4cc * (float)(local_90 - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0xfffffffe,2);
          local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e4 = *(float *)(param_3 + 4) * FLOAT_803df508 * (float)(local_98 - DOUBLE_803df710);
          local_d4 = FLOAT_803df634 * *(float *)(param_3 + 4);
          local_108 = 0x18;
          local_cc = (undefined *)0x1080000;
          local_c8 = 0x1000000;
          local_b0 = 0xa5;
          if (param_6 != (float *)0x0) {
            local_c4 = (uint)*(byte *)param_6 << 8;
            local_b8 = (ushort)local_c4;
            local_c0 = (uint)*(byte *)((int)param_6 + 1) << 8;
            local_b6 = (ushort)local_c0;
            local_bc = (uint)*(byte *)((int)param_6 + 2) << 8;
            local_b4 = (ushort)local_bc;
            local_c8 = 0x1000020;
          }
          local_ce = 0x60;
        }
      }
      else if (iVar9 == 0x5e) {
        uStack164 = FUN_800221a0(0x14,0x1e);
        uStack164 = uStack164 ^ 0x80000000;
        local_a8 = 0x43300000;
        local_d4 = FLOAT_803df4c8 *
                   (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803df710);
        local_108 = 0x1e;
        local_cc = (undefined *)0x80180000;
        local_ce = 0x60;
        if (param_6 != (float *)0x0) {
          local_b8 = *(ushort *)((int)param_6 + 6);
          local_b6 = *(ushort *)(param_6 + 2);
          local_b4 = *(ushort *)((int)param_6 + 10);
          local_c4 = (uint)*(ushort *)param_6;
          local_c0 = (uint)*(ushort *)((int)param_6 + 2);
          local_bc = (uint)*(ushort *)(param_6 + 1);
        }
        local_c8 = 0x8400820;
      }
      else if (iVar9 < 0x5e) {
        if (iVar9 == 0x59) {
          uVar7 = FUN_800221a0(0,4);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803df4f8 - (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0,4);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = FLOAT_803df4f8 -
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0,4);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = FLOAT_803df4f8 -
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(1,0x28);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df524 * (float)(local_90 - DOUBLE_803df710);
          local_108 = 0x28;
          local_cc = (undefined *)0x200;
          local_ce = 0x2b;
        }
        else {
          if (0x58 < iVar9) goto LAB_800aeb28;
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          uVar7 = FUN_800221a0(0xffffff9c,100);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = *(float *)(param_3 + 4) * FLOAT_803df4f0 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(10,200);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = *(float *)(param_3 + 4) *
                     FLOAT_803df4f0 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xffffff9c,100);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = *(float *)(param_3 + 4) *
                     FLOAT_803df4f0 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(8,0xb);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = *(float *)(param_3 + 4) * FLOAT_803df524 * (float)(local_90 - DOUBLE_803df710);
          local_108 = 0x4b;
          local_cc = (undefined *)0x1080000;
          local_c8 = 0x1000000;
          local_ce = 0x77;
          if (param_6 != (float *)0x0) {
            local_c4 = (uint)*(byte *)param_6 << 8;
            local_b8 = (ushort)local_c4;
            local_c0 = (uint)*(byte *)((int)param_6 + 1) << 8;
            local_b6 = (ushort)local_c0;
            local_bc = (uint)*(byte *)((int)param_6 + 2) << 8;
            local_b4 = (ushort)local_bc;
            local_c8 = 0x1000020;
          }
        }
      }
      else {
        local_d4 = FLOAT_803df4e0;
        local_108 = 4;
        local_cc = (undefined *)0x80000;
        local_ce = 0x33;
        local_b8 = 0xffff;
        local_b6 = 0xffff;
        local_b4 = 0xffff;
        local_c4 = 0xffff;
        local_c0 = 0xffff;
        local_bc = 0xffff;
        local_c8 = 0x8000820;
      }
    }
    else if (iVar9 == 0x6a) {
      uVar7 = FUN_800221a0(0xfffffff6,10);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = FLOAT_803df4d0 * (float)(local_78 - DOUBLE_803df710);
      local_dc = FLOAT_803df4dc;
      uStack124 = FUN_800221a0(0xfffffff6,10);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      local_d8 = FLOAT_803df4d0 * (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
      local_ec = FLOAT_803df4dc;
      uStack132 = FUN_800221a0(1,3);
      uStack132 = uStack132 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e8 = FLOAT_803df5d4 * (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
      local_e4 = FLOAT_803df4dc;
      local_d4 = FLOAT_803df4f0;
      local_108 = 0x78;
      local_b0 = 0xff;
      local_af = 0x10;
      local_cc = (undefined *)0x100200;
      local_ce = 0x5f;
    }
    else if (iVar9 < 0x6a) {
      if (iVar9 == 0x67) {
        local_d4 = FLOAT_803df610;
        local_108 = 0x1e;
        local_b0 = 0xff;
        local_cc = (undefined *)0x200;
        local_ce = FUN_800221a0(0,2);
        local_ce = local_ce + 0x156;
      }
      else if (iVar9 < 0x67) {
        if (iVar9 == 0x65) {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          if (param_3 == (short *)0x0) {
            uVar6 = 0xffffffff;
            goto LAB_800aec10;
          }
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          local_c4 = 0xffff;
          local_c0 = 0xffff;
          local_bc = 0xffff;
          local_b8 = 0;
          local_b6 = 0;
          local_b4 = 0;
          local_d4 = FLOAT_803df598;
          local_108 = 100;
          local_b0 = 0xff;
          local_c8 = 0x20;
          local_ce = 0x30;
        }
        else {
          if (iVar9 < 0x65) goto LAB_800aeb28;
          local_af = 0x20;
          local_d4 = FLOAT_803df610;
          local_108 = 0x50;
          local_10c = 0x67;
          local_cc = (undefined *)0x400000;
          local_ce = 0x156;
        }
      }
      else if (iVar9 < 0x69) {
        uVar7 = FUN_800221a0(0xfffffff6,10);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_ec = FLOAT_803df5ec * (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0xfffffff6,10);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_e8 = FLOAT_803df5ec *
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        uStack132 = FUN_800221a0(0xfffffff6,10);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        local_e4 = FLOAT_803df5ec *
                   (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
        local_d4 = FLOAT_803df614;
        local_108 = 0x69;
        local_cc = (undefined *)0x480200;
        local_ce = 0x156;
      }
      else {
        local_d4 = FLOAT_803df688;
        local_108 = 0x44;
        local_cc = (undefined *)0x100201;
        local_ce = 0x60;
      }
    }
    else if (iVar9 == 0x6d) {
      if (param_3 == (short *)0x0) {
        DAT_8039c314 = FLOAT_803df4dc;
        DAT_8039c318 = FLOAT_803df4dc;
        DAT_8039c31c = FLOAT_803df4dc;
        DAT_8039c310 = FLOAT_803df4d0;
        DAT_8039c308 = 0;
        DAT_8039c30a = 0;
        DAT_8039c30c = 0;
        DAT_8039c30e = 0;
        param_3 = &DAT_8039c308;
      }
      if (param_3 == (short *)0x0) {
        uVar6 = 0xffffffff;
        goto LAB_800aec10;
      }
      local_e0 = *(float *)(param_3 + 6);
      local_dc = *(float *)(param_3 + 8);
      local_d8 = *(float *)(param_3 + 10);
      local_d4 = *(float *)(param_3 + 4);
      local_108 = 1;
      local_af = 0;
      local_b0 = 0x19;
      if (param_3[2] != 0) {
        local_b0 = 0x7d;
      }
      local_cc = (undefined *)0xc0012;
      local_ce = 0x77;
    }
    else if (iVar9 < 0x6d) {
      if (iVar9 < 0x6c) {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
          param_3 = &DAT_8039c308;
        }
        if (param_6 == (float *)0x0) {
          uVar6 = 0xffffffff;
          goto LAB_800aec10;
        }
        local_e0 = *(float *)(param_3 + 6);
        local_dc = *(float *)(param_3 + 8);
        local_d8 = *(float *)(param_3 + 10);
        local_ec = *param_6;
        local_e8 = param_6[1];
        local_e4 = param_6[2];
        local_d4 = FLOAT_803df4c8;
        local_108 = 0x28;
        local_78 = (double)(longlong)(int)*(float *)(param_3 + 4);
        local_b0 = (undefined)(int)*(float *)(param_3 + 4);
        local_af = 10;
        local_cc = (undefined *)0x200;
        local_ce = 0xc13;
        local_f8 = FLOAT_803df4dc;
        local_f4 = FLOAT_803df4dc;
        local_f0 = FLOAT_803df4dc;
        local_fc = FLOAT_803df4d0;
        local_100 = 0;
        local_102 = 0;
        local_104 = *param_3;
      }
      else {
        local_d4 = FLOAT_803df568;
        local_108 = 1;
        local_af = 0;
        local_cc = (undefined *)0x11;
        local_c8 = 2;
        local_ce = 0xdd;
      }
    }
    else {
      if (iVar9 < 0x71) goto LAB_800aeb28;
      uVar7 = FUN_800221a0(0xfffffffe,2);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = (float)(local_78 - DOUBLE_803df710);
      local_dc = FLOAT_803df604;
      uStack124 = FUN_800221a0(0xfffffff0,0x10);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
      uStack132 = FUN_800221a0(0xfffffffd,0xffffffff);
      uStack132 = uStack132 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e8 = FLOAT_803df608 * (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
      uVar7 = FUN_800221a0(1,3);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_d4 = FLOAT_803df60c * (float)(local_90 - DOUBLE_803df710);
      local_108 = 100;
      local_b0 = 0x7d;
      local_af = 0x10;
      local_cc = &DAT_80000100;
      local_ce = 0x2c;
    }
  }
  else {
    if (iVar9 == 0x52e) goto LAB_800aeb28;
    if (iVar9 < 0x52e) {
      if (iVar9 == 0x325) {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
        }
        local_d8 = FLOAT_803df6e4;
        local_11c = FLOAT_803df4dc;
        local_118 = FLOAT_803df4dc;
        local_114 = FLOAT_803df4dc;
        local_120 = FLOAT_803df4d0;
        local_124 = FUN_800221a0(0xffff8001,0x7fff);
        local_126 = FUN_800221a0(0xffff8001,0x7fff);
        local_128 = FUN_800221a0(0xffff8001,0x7fff);
        FUN_80021ac8(&local_128,&local_e0);
        local_ec = -(local_e0 / FLOAT_803df4fc);
        local_e8 = -(local_dc / FLOAT_803df4fc);
        local_e4 = -(local_d8 / FLOAT_803df4fc);
        uVar7 = FUN_800221a0(0x9e,0x240);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803df6e8 * (float)(local_78 - DOUBLE_803df710);
        iVar8 = FUN_800221a0(7,0x12);
        local_108 = iVar8 + 0xc;
        local_ce = 0xc98;
        local_cc = (undefined *)0x480110;
        if (param_6 != (float *)0x0) {
          cVar4 = *(char *)param_6;
          if (cVar4 == '\x01') {
            local_c4 = 0x2898;
            local_c0 = 0xffff;
            local_bc = 0xffff;
            local_b8 = 0x6574;
            local_b6 = 0x9f9;
            local_b4 = 0xffff;
            local_c8 = local_c8 | 0x20;
          }
          else if (cVar4 == '\x02') {
            local_c4 = 0xff65;
            local_c0 = 0xd23c;
            local_bc = 0x7fff;
            local_b8 = 0xffc4;
            local_b6 = 0xdc81;
            local_b4 = 0x2603;
            local_c8 = local_c8 | 0x20;
            local_d4 = local_d4 * FLOAT_803df6dc;
          }
          else if (cVar4 == '\x03') {
            local_c4 = 0xfebe;
            local_c0 = 0x5cb2;
            local_bc = 0xfd01;
            local_b8 = 0xfd2c;
            local_b6 = 0x8e5;
            local_b4 = 0x1f5;
            local_c8 = local_c8 | 0x20;
            local_d4 = local_d4 * FLOAT_803df6ec;
          }
        }
      }
      else if (iVar9 < 0x325) {
        if (iVar9 == 0x7f) {
          local_d4 = FLOAT_803df5ec;
          local_108 = 100;
          local_b0 = 0x37;
          local_cc = (undefined *)0x400100;
          if (local_100 == 1) {
            local_ce = 0x15f;
          }
          else if (local_100 < 1) {
            if (local_100 < 0) {
LAB_800a95ac:
              local_ce = 0x15e;
            }
            else {
              local_ce = 0x15e;
            }
          }
          else {
            if (2 < local_100) goto LAB_800a95ac;
            local_ce = 0x15d;
          }
          local_100 = 0;
        }
        else if (iVar9 < 0x7f) {
          if (iVar9 == 0x79) {
            iVar8 = FUN_800221a0(0,1);
            if (iVar8 == 0) {
              local_e0 = FLOAT_803df684;
            }
            else {
              local_e0 = FLOAT_803df64c;
            }
            uVar7 = FUN_800221a0(10,0x3c);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_dc = (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xfffffffd,3);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(1,0x14);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e8 = FLOAT_803df4e8 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            uVar7 = FUN_800221a0(1,7);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df5d0 * (float)(local_90 - DOUBLE_803df710);
            iVar8 = FUN_800221a0(0,0xf);
            local_108 = iVar8 + 0xf;
            local_b0 = 0x9b;
            local_cc = (undefined *)0x100100;
            local_ce = 0x156;
          }
          else if (iVar9 < 0x79) {
            if (iVar9 == 0x76) {
              uVar7 = FUN_800221a0(1,8);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df678 * (float)(local_78 - DOUBLE_803df710);
              iVar8 = FUN_800221a0(0,0x32);
              local_108 = iVar8 + 0x26;
              local_b0 = 0xff;
              local_f8 = FLOAT_803df4dc;
              local_f4 = FLOAT_803df4dc;
              local_f0 = FLOAT_803df4dc;
              local_cc = (undefined *)0x6100110;
              local_ce = 0x159;
            }
            else if (iVar9 < 0x76) {
              if (iVar9 == 0x74) {
                uVar7 = FUN_800221a0(0xffffffb0,0x50);
                local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_e0 = (float)(local_78 - DOUBLE_803df710);
                local_dc = FLOAT_803df4dc;
                uStack124 = FUN_800221a0(0xffffffb0,0x50);
                uStack124 = uStack124 ^ 0x80000000;
                local_80 = 0x43300000;
                local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
                uStack132 = FUN_800221a0(1,4);
                uStack132 = uStack132 ^ 0x80000000;
                local_88 = 0x43300000;
                local_e8 = FLOAT_803df4cc *
                           (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
                local_d4 = FLOAT_803df5ac;
                local_108 = 0x140;
                local_b0 = 0xff;
                local_cc = (undefined *)0x1000204;
                local_ce = 0x151;
              }
              else if (iVar9 < 0x74) {
                uVar7 = FUN_800221a0(4,5);
                local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_d4 = FLOAT_803df61c * (float)(local_78 - DOUBLE_803df710) * FLOAT_803df530;
                local_108 = FUN_800221a0(0x1e,0x28);
                local_cc = (undefined *)0x0;
                local_c8 = 2;
                local_af = 0x10;
                local_ce = 0xdf;
              }
              else {
                local_d4 = FLOAT_803df638;
                local_108 = 0x62;
                local_b0 = 0xff;
                local_d0 = 0xa9;
                local_af = 0;
                local_cc = (undefined *)0x8100210;
                local_ce = 0x159;
              }
            }
            else if (iVar9 < 0x78) {
              uVar7 = FUN_800221a0(0xfffffffc,4);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0,0x28);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0xfffffffc,4);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0xffffffd8,0x28);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803df600 * (float)(local_90 - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0,0x50);
              local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803df66c * (float)(local_98 - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0xffffffd8,0x28);
              local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803df600 * (float)(local_a0 - DOUBLE_803df710);
              uStack164 = FUN_800221a0(0x28,0x50);
              uStack164 = uStack164 ^ 0x80000000;
              local_a8 = 0x43300000;
              local_d4 = FLOAT_803df5a0 *
                         (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803df710);
              iVar8 = FUN_800221a0(0,0x118);
              local_108 = iVar8 + 0x96;
              local_b0 = 0xff;
              local_cc = (undefined *)0x400101;
              local_ce = 0xdf;
            }
            else {
              uVar7 = FUN_800221a0(0,100);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_dc = (float)(local_78 - DOUBLE_803df710);
              local_d4 = FLOAT_803df4cc;
              local_108 = 0x30;
              local_af = 0;
              local_cc = (undefined *)0x8100210;
              local_ce = 0x5e;
            }
          }
          else if (iVar9 == 0x7c) {
            uVar7 = FUN_800221a0(0xffffffe2,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = (float)(DOUBLE_803df5f0 * (double)(float)(local_78 - DOUBLE_803df710));
            uStack124 = FUN_800221a0(0xffffffe2,0x1e);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = (float)(DOUBLE_803df5f0 *
                              (double)(float)((double)CONCAT44(0x43300000,uStack124) -
                                             DOUBLE_803df710));
            local_d4 = FLOAT_803df5f8;
            local_108 = 300;
            local_af = 0;
            local_cc = (undefined *)0x41001c;
            local_ce = 0xc13;
          }
          else if (iVar9 < 0x7c) {
            if (iVar9 < 0x7b) {
              uVar7 = FUN_800221a0(0xfffffffc,4);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0,0x23);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0xfffffffc,4);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0xffffffd8,0x28);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803df600 * (float)(local_90 - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0xffffffd8,0x28);
              local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803df600 * (float)(local_98 - DOUBLE_803df710);
              uVar7 = FUN_800221a0(0,0x50);
              local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803df600 * (float)(local_a0 - DOUBLE_803df710);
              uStack164 = FUN_800221a0(0x28,0x50);
              uStack164 = uStack164 ^ 0x80000000;
              local_a8 = 0x43300000;
              local_d4 = FLOAT_803df5a0 *
                         (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803df710);
              iVar8 = FUN_800221a0(0,0x118);
              local_108 = iVar8 + 0xb4;
              local_b0 = 0;
              local_cc = (undefined *)0xc80404;
              local_ce = 0xdf;
            }
            else {
              uVar7 = FUN_800221a0(0,10);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_dc = FLOAT_803df5e4 + (float)(local_78 - DOUBLE_803df710);
              local_e8 = FLOAT_803df5e8;
              local_d4 = FLOAT_803df508;
              local_108 = 0x50;
              local_af = 0;
              local_cc = (undefined *)0x8100208;
              local_ce = 0x91;
            }
          }
          else if (iVar9 < 0x7e) {
            local_d4 = FLOAT_803df568;
            local_108 = 0x14;
            local_af = 0;
            local_b0 = 0x32;
            local_cc = (undefined *)0x400100;
            local_ce = 0xc13;
          }
          else {
            local_108 = 0x32;
            local_cc = (undefined *)0x400100;
            uVar7 = FUN_800221a0(0xfffffffc,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803df4ec * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xfffffffc,4);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = FLOAT_803df4ec *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0x28,0x50);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e8 = FLOAT_803df5d0 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            uVar7 = FUN_800221a0(0x28,0x50);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df5fc * (float)(local_90 - DOUBLE_803df710);
            if (local_100 == 1) {
              local_ce = 0x160;
            }
            else if (local_100 < 1) {
              if (local_100 < 0) {
LAB_800a97c8:
                local_ce = 0xdf;
              }
              else {
                local_ce = 0xdd;
              }
            }
            else {
              if (2 < local_100) goto LAB_800a97c8;
              local_ce = 0xdf;
            }
            local_100 = 0;
          }
        }
        else if (iVar9 < 0x2bf) {
          if (iVar9 == 0x83) {
            uVar7 = FUN_800221a0(0xffffff60,0xa0);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xffffffce,0xfa);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0xffffff60,0xa0);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e0 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            local_d4 = FLOAT_803df600;
            local_108 = 200;
            local_af = 0x10;
            local_cc = &DAT_80000108;
            local_ce = 0x167;
          }
          else if (iVar9 < 0x83) {
            if (iVar9 == 0x81) {
              uVar7 = FUN_800221a0(0xffffff1a,0xe6);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0xffffffce,0xfa);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0xffffff1a,0xe6);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              local_d4 = FLOAT_803df600;
              local_108 = 200;
              local_af = 0x10;
              local_cc = &DAT_80000108;
              local_ce = 0x165;
            }
            else if (iVar9 < 0x81) {
              local_d4 = FLOAT_803df5cc;
              local_108 = 2;
              local_af = 0;
              local_b0 = 0x32;
              local_cc = (undefined *)0x400110;
              local_ce = 0xdf;
            }
            else {
              uVar7 = FUN_800221a0(0xffffff60,0xa0);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0xffffffce,0xfa);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0xffffff60,0xa0);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e0 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              local_d4 = FLOAT_803df600;
              local_108 = 200;
              local_af = 0x10;
              local_cc = &DAT_80000108;
              local_ce = 0x166;
            }
          }
          else {
            if (iVar9 < 700) goto LAB_800aeb28;
            if (param_3 == (short *)0x0) {
              DAT_8039c314 = FLOAT_803df4dc;
              DAT_8039c318 = FLOAT_803df4dc;
              DAT_8039c31c = FLOAT_803df4dc;
              DAT_8039c310 = FLOAT_803df4d0;
              DAT_8039c308 = 0;
              DAT_8039c30a = 0;
              DAT_8039c30c = 0;
              DAT_8039c30e = 0;
              param_3 = &DAT_8039c308;
            }
            if (param_3 != (short *)0x0) {
              local_e0 = *(float *)(param_3 + 6) - *(float *)(psVar5 + 0xc);
              local_dc = *(float *)(param_3 + 8) - *(float *)(psVar5 + 0xe);
              local_d8 = *(float *)(param_3 + 10) - *(float *)(psVar5 + 0x10);
            }
            local_d4 = FLOAT_803df5a8;
            local_108 = 0x14;
            local_b0 = 0xff;
            local_cc = (undefined *)0x80210;
            local_c8 = 0x100;
            local_ce = (short)uVar17 + -0x28c;
          }
        }
        else if (iVar9 == 0x322) {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          local_d4 = FLOAT_803df504;
          local_108 = 0x50;
          local_cc = (undefined *)0x180200;
          local_c8 = 0x5000000;
          local_ce = 0xc90;
          local_b0 = 0xa5;
        }
        else if (iVar9 < 0x322) {
          if (iVar9 == 800) {
            if (param_3 == (short *)0x0) {
              DAT_8039c314 = FLOAT_803df4dc;
              DAT_8039c318 = FLOAT_803df4dc;
              DAT_8039c31c = FLOAT_803df4dc;
              DAT_8039c310 = FLOAT_803df4d0;
              DAT_8039c308 = 0;
              DAT_8039c30a = 0;
              DAT_8039c30c = 0;
              DAT_8039c30e = 0;
              param_3 = &DAT_8039c308;
            }
            uVar7 = FUN_800221a0(0xfffffffe,2);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803df608 * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(2,5);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803df674 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(1,3);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803df700 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
            local_d4 = FLOAT_803df550;
            local_108 = 0x28;
            local_c8 = 0x5000000;
            local_cc = (undefined *)0x180208;
            local_ce = 0xc8f;
          }
          else {
            if (iVar9 < 800) goto LAB_800aeb28;
            if (param_3 == (short *)0x0) {
              DAT_8039c314 = FLOAT_803df4dc;
              DAT_8039c318 = FLOAT_803df4dc;
              DAT_8039c31c = FLOAT_803df4dc;
              DAT_8039c310 = FLOAT_803df4d0;
              DAT_8039c308 = 0;
              DAT_8039c30a = 0;
              DAT_8039c30c = 0;
              DAT_8039c30e = 0;
              param_3 = &DAT_8039c308;
            }
            uVar7 = FUN_800221a0(0,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e8 = FLOAT_803df4cc * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(2,4);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = FLOAT_803df704 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
            local_d4 = FLOAT_803df4e8;
            local_108 = 100;
            local_cc = (undefined *)0x1180200;
            local_c8 = 0x5000000;
            local_ce = 0xc90;
          }
        }
        else if (iVar9 < 0x324) {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
          }
          uVar7 = FUN_800221a0(0xffffffea,0x15);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df6cc * (float)(local_78 - DOUBLE_803df710) + local_e0;
          uStack124 = FUN_800221a0(0xffffffe9,0x16);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803df6d0 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710) + local_dc;
          uStack132 = FUN_800221a0(0xffffffe9,0x19);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803df6d4 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710) + local_d8;
          uVar7 = FUN_800221a0(1,6);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df6d8 * (float)(local_90 - DOUBLE_803df710);
          iVar8 = FUN_800221a0(7,0xf);
          local_108 = iVar8 + 5;
          local_ce = 0xc9a;
          local_cc = (undefined *)0x100210;
          local_c8 = 0x4000800;
          if (param_6 != (float *)0x0) {
            cVar4 = *(char *)param_6;
            if (cVar4 == '\x01') {
              local_c4 = 0x2898;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0x6574;
              local_b6 = 0x9f9;
              local_b4 = 0xffff;
              local_c8 = 0x4000820;
            }
            else if (cVar4 == '\x02') {
              local_c4 = 0xff65;
              local_c0 = 0xd23c;
              local_bc = 0x7fff;
              local_b8 = 0xffc4;
              local_b6 = 0xdc81;
              local_b4 = 0x2603;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803df6dc;
              local_108 = iVar8 + 0xc;
            }
            else if (cVar4 == '\x03') {
              local_c4 = 0xfebe;
              local_c0 = 0x5cb2;
              local_bc = 0xfd01;
              local_b8 = 0xfd2c;
              local_b6 = 0x8e5;
              local_b4 = 0x1f5;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803df6e0;
              local_108 = iVar8 + 0x19;
            }
            else if (cVar4 == '\x04') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0;
              local_b6 = 0xffff;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803df6e0;
            }
            else if (cVar4 == '\x05') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0xffff;
              local_b6 = 0;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803df6e0;
            }
            else if (cVar4 == '\x06') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0xffff;
              local_b6 = 0x7fff;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803df6e0;
            }
            else if (cVar4 == '\a') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0xffff;
              local_b6 = 0xffff;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803df6e0;
            }
            else if (cVar4 == '\b') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0;
              local_b6 = 0xffff;
              local_b4 = 0xffff;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803df6e0;
            }
          }
        }
      }
      else if (iVar9 == 0x3df) {
        uVar7 = FUN_800221a0(0xffffff9c,100);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = FLOAT_803df4cc * (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0xffffff9c,100);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = FLOAT_803df4cc *
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        uStack132 = FUN_800221a0(0xffffff9c,100);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = FLOAT_803df4cc *
                   (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
        uVar7 = FUN_800221a0(8,10);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e8 = FLOAT_803df608 * (float)(local_90 - DOUBLE_803df710);
        iVar8 = FUN_800221a0(0,0x28);
        if (iVar8 == 0) {
          uVar7 = FUN_800221a0(0x15,0x29);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df4c8 * (float)(local_78 - DOUBLE_803df710);
          local_108 = 0x1cc;
        }
        else {
          uVar7 = FUN_800221a0(8,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df4c8 * (float)(local_78 - DOUBLE_803df710);
          local_108 = FUN_800221a0(0x5a,0x78);
        }
        local_cc = &DAT_80380209;
        local_c8 = 0x5000820;
        local_ce = 0xc0b;
        local_b0 = 0x7f;
        local_c4 = 0x62c0;
        local_c0 = 0xd310;
        local_bc = 0x2800;
        local_b8 = 0x44c0;
        local_b6 = 0xd310;
        local_b4 = 0xb00;
      }
      else if (iVar9 < 0x3df) {
        if (iVar9 == 0x351) {
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          local_e4 = FLOAT_803df708;
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          uVar7 = FUN_800221a0(0x32,100);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df618 * (float)(local_78 - DOUBLE_803df710);
          local_108 = FUN_800221a0(0x28,0x50);
          local_cc = (undefined *)0x8100200;
          local_c8 = 0x5000000;
          local_ce = 0xc8f;
        }
        else if (iVar9 < 0x351) {
          if (iVar9 == 0x328) {
            uVar7 = FUN_800221a0(0xffffff9c,100);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803df568 * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xffffff9c,100);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803df568 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0xffffff9c,100);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803df568 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            local_108 = FUN_800221a0(4,0xd);
            local_cc = (undefined *)0x180210;
            local_c8 = 0x4000800;
            local_d4 = FLOAT_803df6fc;
            local_ce = 0xc9d;
          }
          else if (iVar9 < 0x328) {
            if (0x326 < iVar9) {
LAB_800aeb28:
              uVar6 = 0xffffffff;
              goto LAB_800aec10;
            }
            FUN_800221a0(1,1);
            local_ec = FLOAT_803df4dc;
            FUN_800221a0(1,1);
            local_e8 = FLOAT_803df4dc;
            FUN_800221a0(1,1);
            local_e4 = FLOAT_803df4dc;
            FUN_800221a0(1,1);
            local_e0 = FLOAT_803df4dc;
            FUN_800221a0(1,1);
            local_dc = FLOAT_803df4dc;
            FUN_800221a0(1,1);
            local_d8 = FLOAT_803df4dc;
            uVar7 = FUN_800221a0(10,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df6f0 * (float)(local_78 - DOUBLE_803df710);
            iVar8 = FUN_800221a0(1,1);
            local_108 = iVar8 + 0x17;
            local_ce = 0xc99;
            local_cc = (undefined *)0x180210;
            local_b0 = 0x7d;
            if (param_6 != (float *)0x0) {
              cVar4 = *(char *)param_6;
              if (cVar4 == '\x01') {
                local_c4 = 0x2898;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0x6574;
                local_b6 = 0x9f9;
                local_b4 = 0xffff;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803df6f4;
              }
              else if (cVar4 == '\x02') {
                local_c4 = 0xff65;
                local_c0 = 0xd23c;
                local_bc = 0x7fff;
                local_b8 = 0xffc4;
                local_b6 = 0xdc81;
                local_b4 = 0x2603;
                local_c8 = local_c8 | 0x20;
              }
              else if (cVar4 == '\x03') {
                local_c4 = 0xfebe;
                local_c0 = 0x5cb2;
                local_bc = 0xfd01;
                local_b8 = 0xfd2c;
                local_b6 = 0x8e5;
                local_b4 = 0x1f5;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803df6f8;
              }
              else if (cVar4 == '\x04') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0;
                local_b6 = 0xffff;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803df6e0;
              }
              else if (cVar4 == '\x05') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0xffff;
                local_b6 = 0;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803df6e0;
              }
              else if (cVar4 == '\x06') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0xffff;
                local_b6 = 0x7fff;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803df6e0;
              }
              else if (cVar4 == '\a') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0xffff;
                local_b6 = 0xffff;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803df6e0;
              }
              else if (cVar4 == '\b') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0;
                local_b6 = 0xffff;
                local_b4 = 0xffff;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803df6e0;
              }
            }
          }
          else {
            if (0x329 < iVar9) goto LAB_800aeb28;
            uVar7 = FUN_800221a0(0xffffff9c,100);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803df4cc * (float)(local_78 - DOUBLE_803df710);
            local_dc = FLOAT_803df5b8;
            uStack124 = FUN_800221a0(0xffffff9c,100);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = FLOAT_803df4cc *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(100,200);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_ec = FLOAT_803df4c8 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            uVar7 = FUN_800221a0(100,200);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e8 = FLOAT_803df4c8 * (float)(local_90 - DOUBLE_803df710);
            uVar7 = FUN_800221a0(0xffffff9c,100);
            local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e4 = FLOAT_803df4c8 * (float)(local_98 - DOUBLE_803df710);
            local_cc = (undefined *)0x1081010;
            iVar8 = FUN_800221a0(0,3);
            if (iVar8 == 0) {
              uVar7 = FUN_800221a0(0x28,0x50);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df5bc * (float)(local_78 - DOUBLE_803df710);
              local_b0 = 0x8c;
            }
            else {
              uVar7 = FUN_800221a0(0x28,0x50);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df5c0 * (float)(local_78 - DOUBLE_803df710);
              local_b0 = 10;
              local_cc = (undefined *)((uint)local_cc | 0x100000);
            }
            iVar8 = FUN_800221a0(0,10);
            if (iVar8 == 0) {
              param_4 = param_4 ^ 4 | 1;
            }
            local_108 = 0xdc;
            local_b8 = 0xb1df;
            local_b6 = 0x8acf;
            local_b4 = 0x63bf;
            local_c4 = 0x3caf;
            local_c0 = 0x30f7;
            local_bc = 10000;
            local_c8 = 0x100020;
            local_ce = 0x60;
          }
        }
        else if (iVar9 == 0x3b9) {
          uVar7 = FUN_800221a0(0xffffffec,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803df4e8 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xffffffec,0x14);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e4 = FLOAT_803df4e8 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xffffffce,0x32);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e0 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0xffffffce,0x32);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = (float)(local_90 - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0x1e,100);
          local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_dc = (float)(local_98 - DOUBLE_803df710);
          local_d4 = FLOAT_803df4cc;
          local_108 = 0x4b0;
          local_b0 = 200;
          local_cc = (undefined *)0x180100;
          local_ce = 0x62;
        }
        else if (iVar9 < 0x3b9) {
          if (iVar9 < 0x3b8) goto LAB_800aeb28;
          iVar8 = FUN_800221a0(0,0x78);
          local_78 = (double)CONCAT44(0x43300000,0x3cU - iVar8 ^ 0x80000000);
          local_e0 = FLOAT_803df5c4 * (float)(local_78 - DOUBLE_803df710);
          local_dc = FLOAT_803df580;
          iVar8 = FUN_800221a0(0,0x78);
          uStack124 = 0x3cU - iVar8 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803df5c4 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,0x50);
          uStack132 = 0x28U - iVar8 ^ 0x80000000;
          local_88 = 0x43300000;
          local_ec = FLOAT_803df4e0 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          iVar8 = FUN_800221a0(0,0x50);
          local_90 = (double)CONCAT44(0x43300000,0x28U - iVar8 ^ 0x80000000);
          local_e4 = FLOAT_803df4e0 * (float)(local_90 - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0x28,0x50);
          local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e8 = FLOAT_803df4e0 * (float)(local_98 - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0x28,0x50);
          local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df5a0 * (float)(local_a0 - DOUBLE_803df710);
          local_108 = 0xb4;
          local_af = 0;
          local_cc = (undefined *)0x80400201;
          local_ce = 0x47;
        }
        else {
          if (iVar9 < 0x3de) goto LAB_800aeb28;
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          if (param_3 == (short *)0x0) {
            uVar7 = FUN_800221a0(0xfffffff6,10);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803df4cc * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xfffffff6,10);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_dc = FLOAT_803df4cc *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0xfffffff6,10);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_d8 = FLOAT_803df4cc *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          }
          else {
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
          }
          local_ec = FLOAT_803df4dc;
          local_e8 = FLOAT_803df508;
          local_e4 = FLOAT_803df4dc;
          local_d4 = FLOAT_803df504;
          local_108 = 0x96;
          local_af = 0x1e;
          local_b0 = 0xff;
          local_cc = (undefined *)0x80080209;
          local_c8 = 0x1000020;
          local_ce = 0x5f;
          local_b8 = 0xffff;
          local_b6 = 0xffff;
          local_b4 = 0xa000;
          local_c4 = 0xffff;
          local_c0 = 0xffff;
          local_bc = 0xc000;
        }
      }
      else if (iVar9 == 0x51d) {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
          param_3 = &DAT_8039c308;
        }
        local_104 = 700;
        local_ce = 0xc09;
        local_e0 = *(float *)(param_3 + 6);
        local_dc = *(float *)(param_3 + 8);
        uVar7 = FUN_800221a0(10,0x14);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803df524 * (float)(local_78 - DOUBLE_803df710);
        local_108 = 0xaa;
        local_cc = (undefined *)0xa0104;
        local_f8 = FLOAT_803df4dc;
        local_f4 = FLOAT_803df4dc;
        local_f0 = FLOAT_803df4dc;
        local_102 = 0;
        local_100 = 0;
        local_fc = FLOAT_803df4d0;
      }
      else if (iVar9 < 0x51d) {
        if (iVar9 == 999) {
          local_108 = 300;
          local_cc = (undefined *)0x80400500;
          uVar7 = FUN_800221a0(0xfffffffc,4);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803df4f0 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffffc,4);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e4 = FLOAT_803df550 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0x28,0x50);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803df568 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df5fc * (float)(local_90 - DOUBLE_803df710);
          if (local_100 == 1) {
            local_ce = 0x160;
          }
          else if (local_100 < 1) {
            if (local_100 < 0) {
LAB_800a990c:
              local_ce = 0xdf;
            }
            else {
              local_ce = 0xdd;
            }
          }
          else {
            if (2 < local_100) goto LAB_800a990c;
            local_ce = 0xdf;
          }
          local_100 = 0;
        }
        else if (iVar9 < 999) {
          if (iVar9 < 0x3e6) goto LAB_800aeb28;
          uVar7 = FUN_800221a0(0xfffffffc,4);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffffc,4);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(4,10);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803df674 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df5a0 * (float)(local_90 - DOUBLE_803df710);
          local_108 = 0x15e;
          local_10c = 0x85;
          local_b0 = 0xff;
          local_cc = (undefined *)0x80400201;
          local_ce = 0xdf;
        }
        else if (iVar9 == 0x51b) {
          uVar7 = FUN_800221a0(0,0xf);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df568 * (float)(local_78 - DOUBLE_803df710) + FLOAT_803df550;
          uStack124 = FUN_800221a0(0xffffffce,0x32);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e0 = FLOAT_803df4cc *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xffffffce,0x32);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_dc = FLOAT_803df4cc *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710) +
                     FLOAT_803df580;
          uVar7 = FUN_800221a0(0xffffffce,0x32);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = FLOAT_803df4cc * (float)(local_90 - DOUBLE_803df710);
          local_ec = local_e0 / FLOAT_803df5a4;
          local_e8 = local_dc / FLOAT_803df5a4;
          local_e4 = local_d8 / FLOAT_803df5a4;
          iVar8 = FUN_800221a0(0,0x14);
          local_108 = iVar8 + 0x14;
          local_b0 = 0xff;
          local_cc = (undefined *)0x100110;
          local_ce = 0xe4;
        }
        else {
          if (iVar9 < 0x51b) goto LAB_800aeb28;
          uVar7 = FUN_800221a0(0xffffffe2,0x1e);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df4cc * (float)(local_78 - DOUBLE_803df710);
          local_dc = FLOAT_803df59c;
          uStack124 = FUN_800221a0(0xffffffe2,0x1e);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803df4cc *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0x19,0x23);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803df4e0 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(100,0x96);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df5a0 * (float)(local_90 - DOUBLE_803df710);
          local_108 = FUN_800221a0(0x5a,0x78);
          local_cc = (undefined *)0x80100100;
          local_ce = 0x60;
          local_b8 = 0x7fff;
          local_b6 = 0x7fff;
          local_b4 = 0x7fff;
          iVar8 = FUN_800221a0(0,10);
          local_c4 = iVar8 * 0xacf;
          local_c8 = 0x20;
          local_c0 = local_c4;
          local_bc = local_c4;
        }
      }
      else if (iVar9 == 0x52a) {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
          param_3 = &DAT_8039c308;
        }
        if (param_3 == (short *)0x0) {
          uVar6 = 0xffffffff;
          goto LAB_800aec10;
        }
        local_e0 = *(float *)(param_3 + 6);
        local_dc = *(float *)(param_3 + 8);
        local_d8 = *(float *)(param_3 + 10);
        local_d4 = FLOAT_803df58c;
        local_108 = 10;
        local_b0 = 0xff;
        local_af = 0x10;
        local_cc = (undefined *)0x80440202;
        local_ce = 0x4f9;
        local_c8 = 0x2000000;
      }
      else if (iVar9 < 0x52a) {
        if (iVar9 == 0x51f) {
          local_dc = FLOAT_803df590;
          local_d4 = FLOAT_803df594;
          local_108 = 0x1e;
          local_b0 = 0xff;
          local_af = 0x10;
          local_cc = (undefined *)0x88140200;
          local_ce = 0x159;
        }
        else {
          if (0x51e < iVar9) goto LAB_800aeb28;
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          if (param_3 == (short *)0x0) {
            uVar6 = 0xffffffff;
            goto LAB_800aec10;
          }
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          local_d4 = FLOAT_803df598;
          local_108 = 10;
          local_b0 = 0xff;
          local_af = 0x10;
          local_cc = (undefined *)0x80440202;
          local_ce = 0x156;
        }
      }
      else {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
          param_3 = &DAT_8039c308;
        }
        if (param_3 != (short *)0x0) {
          local_e0 = *(float *)(param_3 + 6) - *(float *)(psVar5 + 0xc);
          local_dc = *(float *)(param_3 + 8) - *(float *)(psVar5 + 0xe);
          local_d8 = *(float *)(param_3 + 10) - *(float *)(psVar5 + 0x10);
        }
        iVar8 = FUN_800221a0(0,0x28);
        if (iVar8 == 0) {
          local_d4 = FLOAT_803df4d4;
        }
        else {
          local_d4 = FLOAT_803df514;
        }
        local_108 = 0x14;
        local_b0 = 0xff;
        local_cc = (undefined *)0x80210;
        local_ce = (short)uVar17 + -0x3d5;
      }
    }
    else if (iVar9 == 0x552) {
      if (param_3 == (short *)0x0) {
        DAT_8039c314 = FLOAT_803df4dc;
        DAT_8039c318 = FLOAT_803df4dc;
        DAT_8039c31c = FLOAT_803df4dc;
        DAT_8039c310 = FLOAT_803df4d0;
        DAT_8039c308 = 0;
        DAT_8039c30a = 0;
        DAT_8039c30c = 0;
        DAT_8039c30e = 0;
      }
      local_d8 = FLOAT_803df518;
      local_d4 = FLOAT_803df4ec;
      local_108 = 0x23;
      local_b0 = 0x9b;
      local_cc = (undefined *)0xa100210;
      local_ce = 0x91;
    }
    else if (iVar9 < 0x552) {
      if (iVar9 == 0x546) {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
          param_3 = &DAT_8039c308;
        }
        local_d4 = FLOAT_803df534 * *(float *)(param_3 + 4);
        local_108 = 4;
        local_cc = (undefined *)0x480000;
        local_c8 = 0x2000002;
        local_ce = 0xc0e;
        local_b0 = 0x73;
      }
      else if (iVar9 < 0x546) {
        if (iVar9 == 0x53c) {
          if (param_6 != (float *)0x0) {
            iVar8 = (int)(FLOAT_803df548 * (FLOAT_803df4d0 - *param_6));
            local_78 = (double)(longlong)iVar8;
            local_b0 = (undefined)iVar8;
            FUN_80137948(s_alpha__d_8031062c);
          }
          local_d4 = FLOAT_803df54c;
          local_cc = (undefined *)0x80000;
          local_c8 = 0x2000002;
          local_108 = 0;
          local_ce = 0xe4;
        }
        else if (iVar9 < 0x53c) {
          if (iVar9 == 0x534) {
            local_dc = FLOAT_803df580;
            uVar7 = FUN_800221a0(0xfffffff1,0xf);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803df4f0 * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xfffffff1,0xf);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803df4f0 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            local_e4 = FLOAT_803df584;
            local_11c = FLOAT_803df4dc;
            local_118 = FLOAT_803df4dc;
            local_114 = FLOAT_803df4dc;
            local_120 = FLOAT_803df4d0;
            local_124 = psVar5[2];
            local_126 = psVar5[1];
            local_128 = *psVar5;
            FUN_80021ac8(&local_128,&local_ec);
            local_b0 = 0xff;
            uStack132 = FUN_800221a0(10,0x14);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_d4 = FLOAT_803df588 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            local_cc = (undefined *)0x2000110;
            local_c8 = 0x200000;
            local_108 = 0x19;
            local_ce = 0x156;
          }
          else if (iVar9 < 0x534) {
            if (iVar9 == 0x532) {
              if (param_3 == (short *)0x0) {
                DAT_8039c314 = FLOAT_803df4dc;
                DAT_8039c318 = FLOAT_803df4dc;
                DAT_8039c31c = FLOAT_803df4dc;
                DAT_8039c310 = FLOAT_803df4d0;
                DAT_8039c308 = 0;
                DAT_8039c30a = 0;
                DAT_8039c30c = 0;
                DAT_8039c30e = 0;
                param_3 = &DAT_8039c308;
              }
              if (param_3 == (short *)0x0) {
                uVar6 = 0xffffffff;
                goto LAB_800aec10;
              }
              local_e0 = *(float *)(param_3 + 6);
              local_dc = *(float *)(param_3 + 8);
              local_d8 = *(float *)(param_3 + 10);
              uVar7 = FUN_800221a0(0xffffffe2,0x1e);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803df568 * (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0xffffffe2,0x1e);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_e8 = FLOAT_803df568 *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0x14,0x1e);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e4 = FLOAT_803df56c *
                         (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              local_11c = FLOAT_803df4dc;
              local_118 = FLOAT_803df4dc;
              local_114 = FLOAT_803df4dc;
              local_120 = FLOAT_803df4d0;
              local_124 = psVar5[2];
              local_126 = psVar5[1];
              local_128 = *psVar5;
              FUN_80021ac8(&local_128,&local_ec);
              local_b0 = 0xcd;
              local_cc = (undefined *)0x100110;
              uVar7 = FUN_800221a0(0x96,200);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df570 * (float)(local_90 - DOUBLE_803df710);
              local_108 = 0x28;
              local_ce = 0x89;
            }
            else if (iVar9 < 0x532) {
              if (param_3 == (short *)0x0) {
                DAT_8039c314 = FLOAT_803df4dc;
                DAT_8039c318 = FLOAT_803df4dc;
                DAT_8039c31c = FLOAT_803df4dc;
                DAT_8039c310 = FLOAT_803df4d0;
                DAT_8039c308 = 0;
                DAT_8039c30a = 0;
                DAT_8039c30c = 0;
                DAT_8039c30e = 0;
                param_3 = &DAT_8039c308;
              }
              if (param_3 != (short *)0x0) {
                local_e0 = *(float *)(param_3 + 6) - *(float *)(psVar5 + 0xc);
                local_dc = *(float *)(param_3 + 8) - *(float *)(psVar5 + 0xe);
                local_d8 = *(float *)(param_3 + 10) - *(float *)(psVar5 + 0x10);
                local_e4 = FLOAT_803df4d8;
              }
              local_d4 = FLOAT_803df514;
              local_108 = 100;
            }
            else {
              if (param_3 == (short *)0x0) {
                DAT_8039c314 = FLOAT_803df4dc;
                DAT_8039c318 = FLOAT_803df4dc;
                DAT_8039c31c = FLOAT_803df4dc;
                DAT_8039c310 = FLOAT_803df4d0;
                DAT_8039c308 = 0;
                DAT_8039c30a = 0;
                DAT_8039c30c = 0;
                DAT_8039c30e = 0;
                param_3 = &DAT_8039c308;
              }
              if (param_3 == (short *)0x0) {
                uVar6 = 0xffffffff;
                goto LAB_800aec10;
              }
              local_e0 = *(float *)(param_3 + 6);
              local_dc = *(float *)(param_3 + 8);
              local_d8 = *(float *)(param_3 + 10);
              uVar7 = FUN_800221a0(0xffffffe2,0x1e);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803df568 * (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(8,10);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_e8 = FLOAT_803df4e8 *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(10,0x1e);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e4 = FLOAT_803df574 *
                         (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              local_11c = FLOAT_803df4dc;
              local_118 = FLOAT_803df4dc;
              local_114 = FLOAT_803df4dc;
              local_120 = FLOAT_803df4d0;
              local_124 = psVar5[2];
              local_126 = psVar5[1];
              local_128 = *psVar5;
              FUN_80021ac8(&local_128,&local_ec);
              uVar7 = FUN_800221a0(8,0x14);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803df4d4 * (float)(local_90 - DOUBLE_803df710);
              local_108 = FUN_800221a0(0x3c,0x78);
              local_cc = (undefined *)0x80180000;
              local_c8 = 0x1400020;
              local_ce = 0xc0b;
              local_b0 = 0x7f;
              local_b8 = 0xffff;
              local_b6 = 0xffff;
              local_b4 = 0xffff;
              local_c4 = 0x3caf;
              local_c0 = 0x3caf;
              local_bc = 0x3caf;
            }
          }
          else {
            if (0x535 < iVar9) goto LAB_800aeb28;
            if (param_3 == (short *)0x0) {
              DAT_8039c314 = FLOAT_803df4dc;
              DAT_8039c318 = FLOAT_803df4dc;
              DAT_8039c31c = FLOAT_803df4dc;
              DAT_8039c310 = FLOAT_803df4d0;
              DAT_8039c308 = 0;
              DAT_8039c30a = 0;
              DAT_8039c30c = 0;
              DAT_8039c30e = 0;
              param_3 = &DAT_8039c308;
            }
            if (param_3 == (short *)0x0) {
              uVar6 = 0xffffffff;
              goto LAB_800aec10;
            }
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
            uVar7 = FUN_800221a0(0xffffffe2,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803df4e8 * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xffffffe2,0x1e);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803df4e8 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0x14,0x1e);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803df578 *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            local_11c = FLOAT_803df4dc;
            local_118 = FLOAT_803df4dc;
            local_114 = FLOAT_803df4dc;
            local_120 = FLOAT_803df4d0;
            local_124 = psVar5[2];
            local_126 = psVar5[1];
            local_128 = *psVar5;
            FUN_80021ac8(&local_128,&local_ec);
            local_b0 = 0xff;
            uVar7 = FUN_800221a0(0x96,200);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df57c * (float)(local_90 - DOUBLE_803df710);
            local_cc = (undefined *)0x2000110;
            local_c8 = 0x2200000;
            local_108 = 0x19;
            local_ce = 0x24;
          }
        }
        else if (iVar9 == 0x53f) {
          local_b0 = 0x37;
          local_d4 = FLOAT_803df4cc;
          local_cc = (undefined *)0x80010;
          local_c8 = 2;
          local_108 = 1;
          local_ce = 0x156;
        }
        else if (iVar9 < 0x53f) {
          if (iVar9 < 0x53e) {
            local_b0 = 0x69;
            local_d4 = FLOAT_803df550;
            local_cc = (undefined *)0x80014;
            local_c8 = 0x22;
            local_108 = 0;
            local_ce = 0x4fe;
            local_b8 = 0xb1df;
            local_b6 = 0xb1df;
            local_b4 = 0xffff;
            local_c4 = 0xb1df;
            local_c0 = 0xb1df;
            local_bc = 0xffff;
            (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
            local_d8 = FLOAT_803df554;
            local_b0 = 0x69;
            local_d4 = FLOAT_803df558;
            local_cc = (undefined *)0x80014;
            local_c8 = 0x22;
            local_b8 = 0xffff;
            local_b6 = 0xb1df;
            local_b4 = 0xffff;
            local_c4 = 0xffff;
            local_c0 = 0xb1df;
            local_bc = 0xffff;
            local_108 = 0;
            local_ce = 0x4ff;
            (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
            local_d8 = FLOAT_803df55c;
            local_b0 = 0x69;
            local_d4 = FLOAT_803df560;
            local_cc = (undefined *)0x80014;
            local_c8 = 0x22;
            local_b8 = 0xb1df;
            local_b6 = 0xffff;
            local_b4 = 0xffff;
            local_c4 = 0xb1df;
            local_c0 = 0xffff;
            local_bc = 0xffff;
            local_108 = 0;
            local_ce = 0x4fe;
          }
          else {
            local_e0 = FLOAT_803df564;
            local_d4 = FLOAT_803df508;
            local_cc = (undefined *)0x80010;
            local_c8 = 2;
            local_108 = 1;
            local_ce = 100;
          }
        }
        else {
          if (iVar9 < 0x545) goto LAB_800aeb28;
          if (param_3 == (short *)0x0) {
            DAT_8039c314 = FLOAT_803df4dc;
            DAT_8039c318 = FLOAT_803df4dc;
            DAT_8039c31c = FLOAT_803df4dc;
            DAT_8039c310 = FLOAT_803df4d0;
            DAT_8039c308 = 0;
            DAT_8039c30a = 0;
            DAT_8039c30c = 0;
            DAT_8039c30e = 0;
            param_3 = &DAT_8039c308;
          }
          local_d4 = FLOAT_803df530 * *(float *)(param_3 + 4);
          local_108 = 4;
          local_cc = (undefined *)0x480000;
          local_c8 = 2;
          local_ce = 0x527;
          local_b0 = 0x69;
        }
      }
      else if (iVar9 == 0x54c) {
        uVar7 = FUN_800221a0(0xfffffff6,10);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = FLOAT_803df508 * (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0xfffffff6,10);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = FLOAT_803df508 *
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        uStack132 = FUN_800221a0(0xfffffff6,10);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = FLOAT_803df508 *
                   (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
        uVar7 = FUN_800221a0(10,0x14);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803df524 * (float)(local_90 - DOUBLE_803df710);
        local_108 = FUN_800221a0(100,0x96);
        local_b0 = 0xff;
        local_cc = (undefined *)0x80480110;
        if (param_6 != (float *)0x0) {
          local_cc = (undefined *)0xc0480110;
        }
        local_ce = 0x157;
      }
      else if (iVar9 < 0x54c) {
        if (iVar9 == 0x549) {
          uVar7 = FUN_800221a0(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df508 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffff6,10);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803df508 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xfffffff6,10);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803df508 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(10,0x14);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df524 * (float)(local_90 - DOUBLE_803df710);
          local_108 = FUN_800221a0(100,0x96);
          local_b0 = 0xff;
          local_cc = (undefined *)0x80480110;
          if (param_6 != (float *)0x0) {
            local_cc = (undefined *)0xc0480110;
          }
          local_ce = 0x85;
        }
        else if (iVar9 < 0x549) {
          if (iVar9 < 0x548) {
            local_e0 = FLOAT_803df538;
            uVar7 = FUN_800221a0(0xffffffb0,0x50);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_dc = (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(0xffffff9c,100);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803df4e8 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            if (param_3 == (short *)0x0) {
              DAT_8039c314 = FLOAT_803df4dc;
              DAT_8039c318 = FLOAT_803df4dc;
              DAT_8039c31c = FLOAT_803df4dc;
              DAT_8039c310 = FLOAT_803df4d0;
              DAT_8039c308 = 0;
              DAT_8039c30a = 0;
              DAT_8039c30c = 0;
              DAT_8039c30e = 0;
            }
            local_d4 = FLOAT_803df53c;
            local_108 = 300;
            local_cc = (undefined *)0x480000;
            local_c8 = 0x2000000;
            local_ce = 0xc0e;
            local_b0 = 0xff;
            local_10c = 0x548;
            local_102 = 0;
            local_104 = 0;
            local_f8 = FLOAT_803df540;
            local_f4 = FLOAT_803df4dc;
            local_f0 = FLOAT_803df4dc;
            local_fc = FLOAT_803df4d0;
            iVar8 = FUN_800221a0(0,0x14);
            local_108 = iVar8 + 0x28;
            local_af = 0x10;
            local_cc = (undefined *)((uint)local_cc | 0x20000);
          }
          else {
            if (param_3 == (short *)0x0) {
              DAT_8039c314 = FLOAT_803df4dc;
              DAT_8039c318 = FLOAT_803df4dc;
              DAT_8039c31c = FLOAT_803df4dc;
              DAT_8039c310 = FLOAT_803df4d0;
              DAT_8039c308 = 0;
              DAT_8039c30a = 0;
              DAT_8039c30c = 0;
              DAT_8039c30e = 0;
            }
            local_d4 = FLOAT_803df544;
            local_108 = 0x50;
            local_cc = (undefined *)0x80201;
            local_c8 = 0x2000000;
            local_ce = 0xc0e;
            local_b0 = 0xff;
          }
        }
        else if (iVar9 < 0x54b) {
          uVar7 = FUN_800221a0(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df508 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffff6,10);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803df508 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xfffffff6,10);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803df508 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(10,0x14);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df524 * (float)(local_90 - DOUBLE_803df710);
          local_108 = FUN_800221a0(100,0x96);
          local_b0 = 0xff;
          local_cc = (undefined *)0x80480110;
          if (param_6 != (float *)0x0) {
            local_cc = (undefined *)0xc0480110;
          }
          local_ce = 0x84;
        }
        else {
          uVar7 = FUN_800221a0(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803df508 * (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffff6,10);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803df508 *
                     (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
          uStack132 = FUN_800221a0(0xfffffff6,10);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803df508 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
          uVar7 = FUN_800221a0(10,0x14);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df524 * (float)(local_90 - DOUBLE_803df710);
          local_108 = FUN_800221a0(100,0x96);
          local_b0 = 0xff;
          local_cc = (undefined *)0x80480110;
          if (param_6 != (float *)0x0) {
            local_cc = (undefined *)0xc0480110;
          }
          local_ce = 0xc0f;
        }
      }
      else if (iVar9 == 0x54f) {
        if (param_6 != (float *)0x0) {
          cVar4 = *(char *)param_6;
        }
        if (cVar4 == '\x01') {
          uVar7 = FUN_800221a0(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df524 * (float)(local_78 - DOUBLE_803df710);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x202;
        }
        else if (cVar4 == '\x02') {
          uVar7 = FUN_800221a0(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df528 * (float)(local_78 - DOUBLE_803df710);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x102;
        }
        else {
          uVar7 = FUN_800221a0(0x12,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df52c * (float)(local_78 - DOUBLE_803df710);
          local_cc = (undefined *)0xc0800;
          local_c8 = 2;
        }
        local_108 = 1;
        local_b0 = 0x60;
        local_ce = 0xc0f;
      }
      else if (iVar9 < 0x54f) {
        if (iVar9 < 0x54e) {
          if (param_6 == (float *)0x0) {
            cVar4 = '\0';
          }
          else {
            cVar4 = *(char *)param_6;
          }
          if (cVar4 == '\x01') {
            uVar7 = FUN_800221a0(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df524 * (float)(local_78 - DOUBLE_803df710);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x202;
          }
          else if (cVar4 == '\x02') {
            uVar7 = FUN_800221a0(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df528 * (float)(local_78 - DOUBLE_803df710);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x102;
          }
          else {
            uVar7 = FUN_800221a0(0x12,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df52c * (float)(local_78 - DOUBLE_803df710);
            local_cc = (undefined *)0xc0800;
            local_c8 = 2;
          }
          local_108 = 1;
          local_b0 = 0x60;
          local_ce = 0x85;
        }
        else {
          if (param_6 != (float *)0x0) {
            cVar4 = *(char *)param_6;
          }
          if (cVar4 == '\x01') {
            uVar7 = FUN_800221a0(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df524 * (float)(local_78 - DOUBLE_803df710);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x202;
          }
          else if (cVar4 == '\x02') {
            uVar7 = FUN_800221a0(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df528 * (float)(local_78 - DOUBLE_803df710);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x102;
          }
          else {
            uVar7 = FUN_800221a0(0x12,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df52c * (float)(local_78 - DOUBLE_803df710);
            local_cc = (undefined *)0xc0800;
            local_c8 = 2;
          }
          local_108 = 1;
          local_b0 = 0x60;
          local_ce = 0x84;
        }
      }
      else if (iVar9 < 0x551) {
        if (param_6 != (float *)0x0) {
          cVar4 = *(char *)param_6;
        }
        if (cVar4 == '\x01') {
          uVar7 = FUN_800221a0(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df524 * (float)(local_78 - DOUBLE_803df710);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x202;
        }
        else if (cVar4 == '\x02') {
          uVar7 = FUN_800221a0(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df528 * (float)(local_78 - DOUBLE_803df710);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x102;
        }
        else {
          uVar7 = FUN_800221a0(0x12,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803df52c * (float)(local_78 - DOUBLE_803df710);
          local_cc = (undefined *)0xc0800;
          local_c8 = 2;
        }
        local_108 = 1;
        local_b0 = 0x60;
        local_ce = 0x157;
      }
      else {
        if (param_3 == (short *)0x0) {
          DAT_8039c314 = FLOAT_803df4dc;
          DAT_8039c318 = FLOAT_803df4dc;
          DAT_8039c31c = FLOAT_803df4dc;
          DAT_8039c310 = FLOAT_803df4d0;
          DAT_8039c308 = 0;
          DAT_8039c30a = 0;
          DAT_8039c30c = 0;
          DAT_8039c30e = 0;
        }
        local_d8 = FLOAT_803df518;
        local_d4 = FLOAT_803df4ec;
        local_108 = 0x23;
        local_b0 = 0x9b;
        local_cc = (undefined *)0x100210;
        local_ce = 0x91;
      }
    }
    else if (iVar9 == 0x55e) {
      if (param_3 == (short *)0x0) {
        DAT_8039c314 = FLOAT_803df4dc;
        DAT_8039c318 = FLOAT_803df4dc;
        DAT_8039c31c = FLOAT_803df4dc;
        DAT_8039c310 = FLOAT_803df4d0;
        DAT_8039c308 = 0;
        DAT_8039c30a = 0;
        DAT_8039c30c = 0;
        DAT_8039c30e = 0;
        param_3 = &DAT_8039c308;
      }
      uVar7 = FUN_800221a0(0xfffffffa,6);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_dc = *(float *)(param_3 + 8) + (float)(local_78 - DOUBLE_803df710);
      uStack124 = FUN_800221a0(0xffffff9c,100);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      local_ec = FLOAT_803df4e8 * (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
      uStack132 = FUN_800221a0(0xffffff9c,100);
      uStack132 = uStack132 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e4 = FLOAT_803df4e8 * (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
      local_d4 = FLOAT_803df514;
      local_108 = 0x12;
      local_b0 = 0xff;
      local_cc = (undefined *)0x400010;
      local_c8 = 0x400008;
      local_ce = 0xe4;
    }
    else if (iVar9 < 0x55e) {
      if (iVar9 == 0x558) {
LAB_800a6aec:
        local_dc = FLOAT_803df4fc;
        if (param_6 == (float *)0x0) {
          local_e8 = FLOAT_803df508;
        }
        else {
          local_e8 = FLOAT_803df50c;
        }
        local_d4 = FLOAT_803df510;
        local_108 = 0xaf;
        local_b0 = 0xff;
        local_cc = (undefined *)0x500010;
        local_c8 = 0x400200;
        local_ce = 0xe4;
        (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
LAB_800a6b6c:
        local_dc = FLOAT_803df4fc;
        if (param_6 == (float *)0x0) {
          local_e8 = FLOAT_803df50c;
        }
        else {
          local_e8 = FLOAT_803df508;
        }
        local_d4 = FLOAT_803df4e0;
        local_108 = 0xaf;
        local_b0 = 0xff;
        local_cc = (undefined *)0x500010;
        local_c8 = 0x400100;
        local_ce = 0xe4;
        (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
      }
      else {
        if (iVar9 < 0x558) {
          if (iVar9 == 0x555) goto LAB_800aeb28;
          if (iVar9 < 0x555) {
            if (iVar9 < 0x554) {
              if (param_3 == (short *)0x0) {
                DAT_8039c314 = FLOAT_803df4dc;
                DAT_8039c318 = FLOAT_803df4dc;
                DAT_8039c31c = FLOAT_803df4dc;
                DAT_8039c310 = FLOAT_803df4d0;
                DAT_8039c308 = 0;
                DAT_8039c30a = 0;
                DAT_8039c30c = 0;
                DAT_8039c30e = 0;
              }
              uVar7 = FUN_800221a0(0xffffffe2,0x1e);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803df4f0 * (float)(local_78 - DOUBLE_803df710);
              uStack124 = FUN_800221a0(0x14,0x1e);
              uStack124 = uStack124 ^ 0x80000000;
              local_80 = 0x43300000;
              local_e8 = FLOAT_803df4ec *
                         (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
              uStack132 = FUN_800221a0(0xffffffe2,0x1e);
              uStack132 = uStack132 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e4 = FLOAT_803df4f0 *
                         (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
              local_d8 = FLOAT_803df518;
              local_11c = FLOAT_803df4dc;
              local_118 = FLOAT_803df4dc;
              local_114 = FLOAT_803df4dc;
              local_120 = FLOAT_803df4d0;
              local_124 = 0;
              local_126 = 0;
              local_128 = *psVar5;
              FUN_80021ac8(&local_128,&local_e0);
              local_d4 = FLOAT_803df520;
              local_108 = 0x91;
              local_b0 = 0xff;
              local_cc = (undefined *)0x3000010;
              local_c8 = 0x2600000;
              local_ce = 0xe4;
            }
            else {
              if (param_3 == (short *)0x0) {
                DAT_8039c314 = FLOAT_803df4dc;
                DAT_8039c318 = FLOAT_803df4dc;
                DAT_8039c31c = FLOAT_803df4dc;
                DAT_8039c310 = FLOAT_803df4d0;
                DAT_8039c308 = 0;
                DAT_8039c30a = 0;
                DAT_8039c30c = 0;
                DAT_8039c30e = 0;
              }
              local_d8 = FLOAT_803df518;
              local_d4 = FLOAT_803df51c;
              local_108 = 0x37;
              local_b0 = 0x9b;
              local_cc = (undefined *)0xa100210;
              local_ce = 0x73;
            }
            goto LAB_800aeb30;
          }
          if (iVar9 < 0x557) {
            local_dc = FLOAT_803df4fc;
            local_d4 = FLOAT_803df500;
            local_108 = 0xaf;
            local_b0 = 0xff;
            local_cc = (undefined *)0x500010;
            local_c8 = 0x400200;
            local_ce = 0xe4;
            (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
            goto LAB_800a69a8;
          }
LAB_800a6a6c:
          local_dc = FLOAT_803df4fc;
          if (param_6 == (float *)0x0) {
            local_e8 = FLOAT_803df50c;
          }
          else {
            local_e8 = FLOAT_803df508;
          }
          local_d4 = FLOAT_803df510;
          local_108 = 0xaf;
          local_b0 = 0xff;
          local_cc = (undefined *)0x500010;
          local_c8 = 0x400200;
          local_ce = 0xe4;
          (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
          goto LAB_800a6aec;
        }
        if (iVar9 != 0x55b) {
          if (0x55a < iVar9) {
            if (iVar9 < 0x55d) {
LAB_800a69a8:
              local_dc = FLOAT_803df4fc;
              local_d4 = FLOAT_803df4e8;
              local_108 = 0xaf;
              local_b0 = 0xff;
              local_cc = (undefined *)0x500010;
              local_c8 = 0x400100;
              local_ce = 0xe4;
              (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
            }
            local_dc = FLOAT_803df4fc;
            local_d4 = FLOAT_803df504;
            local_108 = 0x2d;
            local_b0 = 0xff;
            local_cc = (undefined *)0x100210;
            local_c8 = 0x200;
            local_ce = 0xe4;
            (**(code **)(*DAT_803dca78 + 8))(&local_110,0,iVar9,0);
            goto LAB_800a6a6c;
          }
          if (0x559 < iVar9) {
            if (param_3 == (short *)0x0) {
              DAT_8039c314 = FLOAT_803df4dc;
              DAT_8039c318 = FLOAT_803df4dc;
              DAT_8039c31c = FLOAT_803df4dc;
              DAT_8039c310 = FLOAT_803df4d0;
              DAT_8039c308 = 0;
              DAT_8039c30a = 0;
              DAT_8039c30c = 0;
              DAT_8039c30e = 0;
            }
            uVar7 = FUN_800221a0(0xffffffd8,0x28);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803df5cc * (float)(local_78 - DOUBLE_803df710);
            uStack124 = FUN_800221a0(10,0x50);
            uStack124 = uStack124 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803df568 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
            uStack132 = FUN_800221a0(0xffffffd8,0x28);
            uStack132 = uStack132 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803df5cc *
                       (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
            uVar7 = FUN_800221a0(5,0x19);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803df528 * (float)(local_90 - DOUBLE_803df710);
            local_108 = FUN_800221a0(0x122,0x15e);
            local_b0 = 0xff;
            local_104 = FUN_800221a0(0,0xffff);
            local_102 = FUN_800221a0(0,0xffff);
            local_104 = FUN_800221a0(0,0xffff);
            uVar7 = FUN_800221a0(0xe6,800);
            local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_f8 = (float)(local_98 - DOUBLE_803df710);
            uVar7 = FUN_800221a0(0xe6,800);
            local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_f4 = (float)(local_a0 - DOUBLE_803df710);
            uStack164 = FUN_800221a0(0xe6,800);
            uStack164 = uStack164 ^ 0x80000000;
            local_a8 = 0x43300000;
            local_f0 = (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803df710);
            local_c8 = 0x1000020;
            local_cc = (undefined *)0x86000008;
            iVar8 = FUN_800221a0(0,0xfff);
            local_c4 = iVar8 + 0xf000;
            local_b8 = (ushort)local_c4;
            local_c0 = 0xe000;
            local_b6 = 0xe000;
            local_bc = 0xe000;
            local_b4 = 0xe000;
            local_ce = 0x567;
            goto LAB_800aeb30;
          }
          goto LAB_800a6b6c;
        }
      }
      local_dc = FLOAT_803df4fc;
      if (param_6 == (float *)0x0) {
        local_e8 = FLOAT_803df508;
      }
      else {
        local_e8 = FLOAT_803df50c;
      }
      local_d4 = FLOAT_803df4e0;
      local_108 = 0xaf;
      local_b0 = 0xff;
      local_cc = (undefined *)0x500010;
      local_c8 = 0x400100;
      local_ce = 0xe4;
    }
    else if (iVar9 == 0x68c) {
      local_d4 = FLOAT_803df4e8;
      local_108 = 0x5f;
      local_cc = (undefined *)0x1180200;
      local_ce = 0x62;
      local_b8 = 0;
      local_b6 = 0;
      local_b4 = FUN_800221a0(0x8000);
      local_c4 = 0;
      local_c0 = FUN_800221a0(0,0x8000);
      local_bc = FUN_800221a0(0,0xffff);
      local_c8 = 0x20;
    }
    else if (iVar9 < 0x68c) {
      if (iVar9 == 0x565) {
        local_d4 = FLOAT_803df4d0;
        local_108 = 0x14;
        local_af = 0;
        local_cc = (undefined *)0x210;
        local_c8 = 0x800;
        local_ce = 0x5b1;
      }
      else if (iVar9 < 0x565) {
        if (iVar9 < 0x564) goto LAB_800aeb28;
        uVar7 = FUN_800221a0(0x32,100);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803df5a0 * (float)(local_78 - DOUBLE_803df710);
        local_108 = 0x2d;
        local_cc = (undefined *)0x80580210;
        local_b0 = 0xff;
        local_ce = 0xc0f;
      }
      else {
        if (iVar9 < 0x68b) goto LAB_800aeb28;
        if (param_3 == (short *)0x0) {
          uVar7 = FUN_800221a0(0xfffffff9,7);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803df710);
          uStack124 = FUN_800221a0(0xfffffff9,7);
          uStack124 = uStack124 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        }
        else {
          local_e0 = *(float *)(param_3 + 6) - *(float *)(psVar5 + 0xc);
          local_d8 = *(float *)(param_3 + 10) - *(float *)(psVar5 + 0x10);
        }
        local_dc = FLOAT_803df4f8;
        uVar7 = FUN_800221a0(0xffffffce,0x32);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_ec = FLOAT_803df4e4 * (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0,0x32);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_e8 = FLOAT_803df4e4 *
                   (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        uStack132 = FUN_800221a0(0xffffffce,0x32);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        local_e4 = FLOAT_803df4e4 *
                   (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
        local_d4 = FLOAT_803df4e8;
        if (param_3 != (short *)0x0) {
          local_d4 = *(float *)(param_3 + 4);
        }
        local_108 = 0x32;
        local_b0 = 0x96;
        local_cc = (undefined *)0x80080200;
        local_ce = 0x62;
        local_b8 = FUN_800221a0(0,0xffff);
        local_b6 = 0;
        local_b4 = 0;
        local_c4 = 0xffff;
        local_c0 = 0xffff;
        local_bc = 0;
        local_c8 = 0x1000020;
      }
    }
    else if (iVar9 == 0x68f) {
      uVar7 = FUN_800221a0(0xfffffff9,7);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = (float)(local_78 - DOUBLE_803df710);
      uStack124 = FUN_800221a0(0xfffffff9,7);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
      uStack132 = FUN_800221a0(0xfffffff9,7);
      uStack132 = uStack132 ^ 0x80000000;
      local_88 = 0x43300000;
      local_d8 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xffffffce,0x32);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_ec = FLOAT_803df4e4 * (float)(local_90 - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xffffffce,0x32);
      local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e8 = FLOAT_803df4e4 * (float)(local_98 - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xffffffce,0x32);
      local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e4 = FLOAT_803df4e4 * (float)(local_a0 - DOUBLE_803df710);
      local_d4 = FLOAT_803df4f0;
      local_108 = 100;
      local_b0 = 0x96;
      local_cc = (undefined *)0x1080200;
      local_ce = 0x62;
      local_b8 = FUN_800221a0(0,0xffff);
      local_b6 = 0;
      local_b4 = 0;
      local_c4 = 0xffff;
      local_c0 = 0xffff;
      local_bc = 0;
      local_c8 = 0x20;
    }
    else if (iVar9 < 0x68f) {
      if (iVar9 < 0x68e) {
        uVar7 = FUN_800221a0(0xfffffff9,7);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = (float)(local_78 - DOUBLE_803df710);
        uStack124 = FUN_800221a0(0xfffffff9,7);
        uStack124 = uStack124 ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
        uStack132 = FUN_800221a0(0xfffffff9,7);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
        uVar7 = FUN_800221a0(0xffffffce,0x32);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_ec = FLOAT_803df4e4 * (float)(local_90 - DOUBLE_803df710);
        uVar7 = FUN_800221a0(0xffffffce,0x32);
        local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e8 = FLOAT_803df4e4 * (float)(local_98 - DOUBLE_803df710);
        uVar7 = FUN_800221a0(0xffffffce,0x32);
        local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e4 = FLOAT_803df4e4 * (float)(local_a0 - DOUBLE_803df710);
        local_d4 = FLOAT_803df4e8;
        local_108 = 0x5a;
        local_b0 = 0x96;
        local_cc = (undefined *)0x1080200;
        local_ce = 0x62;
        local_b8 = 0;
        local_b6 = 0;
        local_b4 = FUN_800221a0(0,0xffff);
        local_c4 = 0x7fff;
        local_c0 = 0xffff;
        local_bc = 0xffff;
        local_c8 = 0x20;
      }
      else {
        local_d4 = FLOAT_803df4ec;
        local_108 = 0x5f;
        local_cc = (undefined *)0x180208;
        local_ce = 0x62;
        local_b8 = FUN_800221a0(0x8000);
        local_b6 = 0;
        local_b4 = 0;
        local_c4 = FUN_800221a0(0,0xffff);
        local_c0 = FUN_800221a0(0,0x8000);
        local_bc = 0;
        local_c8 = 0x20;
      }
    }
    else {
      if (0x690 < iVar9) goto LAB_800aeb28;
      uVar7 = FUN_800221a0(0xfffffff9,7);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = (float)(local_78 - DOUBLE_803df710);
      uStack124 = FUN_800221a0(0xfffffff9,7);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      local_dc = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df710);
      uStack132 = FUN_800221a0(0xfffffff9,7);
      uStack132 = uStack132 ^ 0x80000000;
      local_88 = 0x43300000;
      local_d8 = (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xffffffce,0x32);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_ec = FLOAT_803df4e4 * (float)(local_90 - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0x14,0x32);
      local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e8 = FLOAT_803df4f4 * (float)(local_98 - DOUBLE_803df710);
      uVar7 = FUN_800221a0(0xffffffce,0x32);
      local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e4 = FLOAT_803df4e4 * (float)(local_a0 - DOUBLE_803df710);
      local_d4 = FLOAT_803df4f0;
      local_108 = 0x96;
      local_b0 = 0x96;
      local_cc = (undefined *)0x80208;
      local_ce = 0x62;
      local_b8 = 0xffff;
      local_b6 = 0;
      local_b4 = 0;
      local_c4 = 0xffff;
      local_c0 = 0xffff;
      local_bc = 0xffff;
      local_c8 = 0x20;
    }
  }
LAB_800aeb30:
  local_cc = (undefined *)((uint)local_cc | param_4);
  if ((((uint)local_cc & 1) != 0) && (((uint)local_cc & 2) != 0)) {
    local_cc = (undefined *)((uint)local_cc ^ 2);
  }
  if (((uint)local_cc & 1) != 0) {
    if ((param_4 & 0x200000) == 0) {
      if (local_110 != (short *)0x0) {
        local_e0 = local_e0 + *(float *)(local_110 + 0xc);
        local_dc = local_dc + *(float *)(local_110 + 0xe);
        local_d8 = local_d8 + *(float *)(local_110 + 0x10);
      }
    }
    else {
      local_e0 = local_e0 + local_f8;
      local_dc = local_dc + local_f4;
      local_d8 = local_d8 + local_f0;
    }
  }
  uVar6 = (**(code **)(*DAT_803dca78 + 8))(&local_110,0xffffffff,iVar9,0);
LAB_800aec10:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  __psq_l0(auStack56,uVar11);
  __psq_l1(auStack56,uVar11);
  __psq_l0(auStack72,uVar11);
  __psq_l1(auStack72,uVar11);
  FUN_80286120(uVar6);
  return;
}

