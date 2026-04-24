// Function: FUN_800a5080
// Entry: 800a5080
// Size: 40540 bytes

/* WARNING: Removing unreachable block (ram,0x800aeebc) */
/* WARNING: Removing unreachable block (ram,0x800aeeb4) */
/* WARNING: Removing unreachable block (ram,0x800aeeac) */
/* WARNING: Removing unreachable block (ram,0x800aeea4) */
/* WARNING: Removing unreachable block (ram,0x800aee9c) */
/* WARNING: Removing unreachable block (ram,0x800aaa90) */
/* WARNING: Removing unreachable block (ram,0x800aaad0) */
/* WARNING: Removing unreachable block (ram,0x800aaa9c) */
/* WARNING: Removing unreachable block (ram,0x800a50b0) */
/* WARNING: Removing unreachable block (ram,0x800a50a8) */
/* WARNING: Removing unreachable block (ram,0x800a50a0) */
/* WARNING: Removing unreachable block (ram,0x800a5098) */
/* WARNING: Removing unreachable block (ram,0x800a5090) */

void FUN_800a5080(undefined4 param_1,undefined4 param_2,short *param_3,uint param_4,
                 undefined4 param_5,float *param_6)

{
  int iVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  ushort *puVar6;
  uint uVar7;
  int iVar8;
  short sVar9;
  double in_f27;
  double dVar10;
  double in_f28;
  double dVar11;
  double in_f29;
  double dVar12;
  double in_f30;
  double dVar13;
  double in_f31;
  double dVar14;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  ushort local_128;
  ushort local_126;
  ushort local_124;
  float local_120;
  float local_11c;
  float local_118;
  float local_114;
  ushort *local_110;
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
  uint uStack_a4;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined8 local_78;
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
  uVar15 = FUN_80286838();
  puVar6 = (ushort *)((ulonglong)uVar15 >> 0x20);
  iVar8 = (int)uVar15;
  if (((899 < iVar8) && (iVar8 < 0x3b5)) || ((0x5dc < iVar8 && (iVar8 < 0x641)))) {
    DAT_8039cf40 = 2000;
    if (DAT_803ddf48 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf48 = (int *)FUN_80013ee8(0x1a);
    }
    (**(code **)(*DAT_803ddf48 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((599 < iVar8) && (iVar8 < 700)) {
    DAT_8039cf42 = 2000;
    if (DAT_803ddf4c == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf4c = (int *)FUN_80013ee8(0x1b);
    }
    (**(code **)(*DAT_803ddf4c + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((499 < iVar8) && (iVar8 < 600)) {
    DAT_8039cf44 = 2000;
    if (DAT_803ddf50 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf50 = (int *)FUN_80013ee8(0x1c);
    }
    (**(code **)(*DAT_803ddf50 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((399 < iVar8) && (iVar8 < 500)) {
    DAT_8039cf46 = 2000;
    if (DAT_803ddf54 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf54 = (int *)FUN_80013ee8(0x1d);
    }
    (**(code **)(*DAT_803ddf54 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((199 < iVar8) && (iVar8 < 300)) {
    DAT_8039cf48 = 2000;
    if (DAT_803ddf58 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf58 = (int *)FUN_80013ee8(0x1e);
    }
    (**(code **)(*DAT_803ddf58 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x419 < iVar8) && (iVar8 < 0x44c)) {
    DAT_8039cf4a = 2000;
    if (DAT_803ddf5c == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf5c = (int *)FUN_80013ee8(0x1f);
    }
    (**(code **)(*DAT_803ddf5c + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x739 < iVar8) && (iVar8 < 0x76c)) {
    DAT_8039cf60 = 2000;
    if (DAT_803ddf60 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf60 = (int *)FUN_80013ee8(0x2a);
    }
    (**(code **)(*DAT_803ddf60 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((iVar8 - 0x84U < 2) || ((0x89 < iVar8 && (iVar8 < 200)))) {
    DAT_8039cf4c = 2000;
    if (DAT_803ddf64 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf64 = (int *)FUN_80013ee8(0x20);
    }
    (**(code **)(*DAT_803ddf64 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x3b5 < iVar8) && (iVar8 < 0x3de)) {
    DAT_8039cf50 = 2000;
    if (DAT_803ddf6c == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf6c = (int *)FUN_80013ee8(0x22);
    }
    (**(code **)(*DAT_803ddf6c + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x351 < iVar8) && (iVar8 < 900)) {
    DAT_8039cf4e = 2000;
    if (DAT_803ddf68 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf68 = (int *)FUN_80013ee8(0x21);
    }
    (**(code **)(*DAT_803ddf68 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x329 < iVar8) && (iVar8 < 0x351)) {
    DAT_8039cf52 = 2000;
    if (DAT_803ddf70 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf70 = (int *)FUN_80013ee8(0x23);
    }
    (**(code **)(*DAT_803ddf70 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((299 < iVar8) && (iVar8 < 400)) {
    DAT_8039cf54 = 2000;
    if (DAT_803ddf74 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf74 = (int *)FUN_80013ee8(0x24);
    }
    (**(code **)(*DAT_803ddf74 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x47d < iVar8) && (iVar8 < 0x4b0)) {
    DAT_8039cf56 = 2000;
    if (DAT_803ddf78 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf78 = (int *)FUN_80013ee8(0x25);
    }
    (**(code **)(*DAT_803ddf78 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x4af < iVar8) && (iVar8 < 0x4e2)) {
    DAT_8039cf58 = 2000;
    if (DAT_803ddf7c == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf7c = (int *)FUN_80013ee8(0x27);
    }
    (**(code **)(*DAT_803ddf7c + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((999 < iVar8) && (iVar8 < 0x41a)) {
    DAT_8039cf5a = 2000;
    if (DAT_803ddf80 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf80 = (int *)FUN_80013ee8(0x28);
    }
    (**(code **)(*DAT_803ddf80 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((1099 < iVar8) && (iVar8 < 0x47e)) {
    DAT_8039cf5c = 2000;
    if (DAT_803ddf84 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf84 = (int *)FUN_80013ee8(0x26);
    }
    (**(code **)(*DAT_803ddf84 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x6d6 < iVar8) && (iVar8 < 0x708)) {
    DAT_8039cf5e = 2000;
    if (DAT_803ddf88 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf88 = (int *)FUN_80013ee8(0x29);
    }
    (**(code **)(*DAT_803ddf88 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x707 < iVar8) && (iVar8 < 0x73a)) {
    DAT_8039cf62 = 2000;
    if (DAT_803ddf8c == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf8c = (int *)FUN_80013ee8(0x2b);
    }
    (**(code **)(*DAT_803ddf8c + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x76b < iVar8) && (iVar8 < 0x79e)) {
    DAT_8039cf64 = 2000;
    if (DAT_803ddf90 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf90 = (int *)FUN_80013ee8(0x2c);
    }
    (**(code **)(*DAT_803ddf90 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  if ((0x79d < iVar8) && (iVar8 < 0x834)) {
    DAT_8039cf66 = 2000;
    if (DAT_803ddf94 == (int *)0x0) {
      DAT_803ddf40 = DAT_803ddf40 + '\x01';
      DAT_803ddf94 = (int *)FUN_80013ee8(0x2d);
    }
    (**(code **)(*DAT_803ddf94 + 8))(puVar6,iVar8,param_3,param_4,param_5,param_6);
    goto LAB_800aee9c;
  }
  FLOAT_803dc400 = FLOAT_803dc400 + FLOAT_803e0148;
  if (FLOAT_803e0150 < FLOAT_803dc400) {
    FLOAT_803dc400 = FLOAT_803e014c;
  }
  FLOAT_803dc404 = FLOAT_803dc404 + FLOAT_803e0154;
  if (FLOAT_803e0150 < FLOAT_803dc404) {
    FLOAT_803dc404 = FLOAT_803e0158;
  }
  if (puVar6 == (ushort *)0x0) goto LAB_800aee9c;
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (short *)0x0) goto LAB_800aee9c;
    local_f8 = *(float *)(param_3 + 6);
    local_f4 = *(float *)(param_3 + 8);
    local_f0 = *(float *)(param_3 + 10);
    local_fc = *(float *)(param_3 + 4);
    local_100 = param_3[2];
    local_102 = param_3[1];
    local_104 = *param_3;
    local_ae = (undefined)param_5;
  }
  cVar5 = '\0';
  local_cc = (undefined *)0x0;
  local_c8 = 0;
  local_b2 = (undefined)uVar15;
  local_e0 = FLOAT_803e015c;
  local_dc = FLOAT_803e015c;
  local_d8 = FLOAT_803e015c;
  local_ec = FLOAT_803e015c;
  local_e8 = FLOAT_803e015c;
  local_e4 = FLOAT_803e015c;
  local_d4 = FLOAT_803e015c;
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
  local_110 = puVar6;
  if (iVar8 == 0x72) {
    uVar7 = FUN_80022264(1,4);
    local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
    local_d4 = FLOAT_803e0298 * (float)(local_78 - DOUBLE_803e0390);
    local_108 = FUN_80022264(0x1e,0x3c);
    local_cc = (undefined *)0x80100;
    local_c8 = 0x4000802;
    local_af = 0;
    local_ce = 0xde;
    uVar7 = FUN_80022264(0x96,0xfa);
    local_b0 = (undefined)uVar7;
  }
  else if (iVar8 < 0x72) {
    if (iVar8 == 0x34) {
      local_d4 = FLOAT_803e0288;
      local_108 = 0x1e;
      local_af = 0x20;
      local_cc = (undefined *)0x400210;
      local_ce = 0x71;
    }
    else if (iVar8 < 0x34) {
      if (iVar8 == 0x1b) {
        uVar7 = FUN_80022264(0,0x3c);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e8 = FLOAT_803e0170 * (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0,4);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_d4 = FLOAT_803e0310 *
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uVar7 = FUN_80022264(0,3);
        uStack_84 = uVar7 + 1 ^ 0x80000000;
        local_88 = 0x43300000;
        local_108 = (uint)(FLOAT_803e0320 *
                          (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390));
        local_90 = (double)(longlong)(int)local_108;
        local_af = 5;
        local_cc = (undefined *)0x1000211;
        local_ce = 0x30;
      }
      else if (iVar8 < 0x1b) {
        if (iVar8 == 0xb) goto LAB_800aee9c;
        if (iVar8 < 0xb) {
          if (iVar8 == 5) {
            if (param_3 == (short *)0x0) goto LAB_800aee9c;
            uVar7 = FUN_80022264(0xffffffe2,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803e0258 * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xffffffe2,0x1e);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_dc = FLOAT_803e0258 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0xffffffe2,0x1e);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_d8 = FLOAT_803e0258 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0xf,0x23);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e8 = FLOAT_803e0164 * (float)(local_90 - DOUBLE_803e0390);
            uVar7 = FUN_80022264(100,0x96);
            local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e025c * (float)(local_98 - DOUBLE_803e0390);
            local_108 = FUN_80022264(0x32,0x50);
            uVar7 = FUN_80022264(10,0x1e);
            local_af = (undefined)uVar7;
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
          else if (iVar8 < 5) {
            if (iVar8 == 2) {
              uVar7 = FUN_80022264(0xffffffec,0x14);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = FLOAT_803e02b8 * (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0xffffffec,0x14);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = FLOAT_803e02b8 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0xffffffec,0x14);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = FLOAT_803e02b8 *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0,0x1e);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e0148 * (float)(local_90 - DOUBLE_803e0390) + FLOAT_803e030c;
              local_108 = FUN_80022264(0,8);
              local_108 = local_108 + 8;
              local_b0 = 0xff;
              local_cc = (undefined *)0x100100;
              local_ce = 0x33;
            }
            else if (iVar8 < 2) {
              if (iVar8 == 0) {
                local_d4 = FLOAT_803e0168;
                local_108 = 6;
                local_d0 = 0;
                local_cc = (undefined *)0x10;
                local_ce = 0x87;
              }
              else {
                if (iVar8 < 0) goto LAB_800aee9c;
                local_dc = FLOAT_803e0248;
                uVar7 = FUN_80022264(0xfffffff1,0xf);
                local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_ec = FLOAT_803e01e8 * FLOAT_803dc408 * (float)(local_78 - DOUBLE_803e0390);
                uStack_7c = FUN_80022264(5,0x14);
                uStack_7c = uStack_7c ^ 0x80000000;
                local_80 = 0x43300000;
                local_e8 = FLOAT_803e0234 *
                           (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
                uStack_84 = FUN_80022264(0xfffffff1,0xf);
                uStack_84 = uStack_84 ^ 0x80000000;
                local_88 = 0x43300000;
                local_e4 = FLOAT_803e01e8 * FLOAT_803dc408 *
                           (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
                uVar7 = FUN_80022264(0,10);
                local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_d4 = FLOAT_803e01a4 * (float)(local_90 - DOUBLE_803e0390) + FLOAT_803e0234;
                local_b0 = 0xff;
                local_af = 0xf;
                local_cc = (undefined *)0x588008;
                local_c8 = 0x10000;
                local_ce = 0x23b;
                local_10c = 4;
              }
            }
            else if (iVar8 < 4) {
              if (param_3 == (short *)0x0) goto LAB_800aee9c;
              uVar7 = FUN_80022264(0x14,0x3c);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_dc = FLOAT_803e0158 * (float)(local_78 - DOUBLE_803e0390);
              local_d4 = FLOAT_803e0254;
              local_108 = 0x23;
              local_b0 = 0x96;
              local_af = 0x14;
              local_cc = (undefined *)0x9100110;
              local_c8 = 0x4000000;
              local_ce = param_3[2];
            }
            else {
              uVar7 = FUN_80022264(10,0x14);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803e024c * (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0,10);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_d4 = FLOAT_803e01a4 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390) +
                         FLOAT_803e0250;
              local_108 = 0x3c;
              local_b0 = 0xcd;
              local_af = 6;
              local_cc = (undefined *)0xa100200;
              local_ce = 0x47;
            }
          }
          else if (iVar8 == 8) {
            local_dc = FLOAT_803e02c4;
            local_d4 = FLOAT_803e016c;
            local_108 = 0x30;
            local_b0 = 200;
            local_cc = (undefined *)0x300002;
            local_ce = 0x2c;
          }
          else if (iVar8 < 8) {
            if (iVar8 < 7) {
              local_d4 = FLOAT_803e02a4;
              local_108 = 0x12;
              local_cc = (undefined *)0x300200;
              local_ce = 0x33;
            }
            else {
              if (param_3 == (short *)0x0) goto LAB_800aee9c;
              uVar7 = FUN_80022264(0xffffffe2,0x1e);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = FLOAT_803e0258 * (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0xffffffe2,0x1e);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = FLOAT_803e0258 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0xffffffe2,0x1e);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = FLOAT_803e0258 *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0xffffffd8,0x28);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803e0260 * (float)(local_90 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(10,0x28);
              local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803e0260 * (float)(local_98 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0xffffffd8,0x28);
              local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803e0260 * (float)(local_a0 - DOUBLE_803e0390);
              local_d4 = FLOAT_803e01e8;
              local_108 = FUN_80022264(0x14,0x32);
              local_af = 0x1e;
              local_cc = (undefined *)0x511;
              local_c8 = 0x4000000;
              local_ce = param_3[2];
            }
          }
          else if (iVar8 < 10) {
            local_dc = FLOAT_803e02c4;
            local_d8 = FLOAT_803e0238;
            local_d4 = FLOAT_803e016c;
            local_108 = 0x3c;
            local_b0 = 200;
            local_cc = (undefined *)0x300000;
            local_ce = 0x2c;
          }
          else {
            local_d4 = FLOAT_803e016c;
            local_108 = 0x3c;
            local_b0 = 200;
            local_cc = (undefined *)0x300000;
            local_ce = 0x2c;
          }
        }
        else if (iVar8 == 0x12) {
          local_dc = FLOAT_803e02b0;
          local_d4 = FLOAT_803e0160;
          local_108 = 0x14d;
          local_cc = (undefined *)0x10012;
          local_ce = 0x33;
        }
        else if (iVar8 < 0x12) {
          if (iVar8 == 0xf) {
            local_e0 = FLOAT_803e0318;
            local_dc = FLOAT_803e02b0;
            local_d8 = FLOAT_803e0210;
            uVar7 = FUN_80022264(0,0xa0);
            local_78 = (double)CONCAT44(0x43300000,0x50 - uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e0164 * (float)(local_78 - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0,0xa0);
            uStack_7c = 0x50 - uVar7 ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = FLOAT_803e0164 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            local_d4 = FLOAT_803e0160;
            uVar7 = FUN_80022264(0,3);
            uStack_84 = uVar7 + 1 ^ 0x80000000;
            local_88 = 0x43300000;
            local_108 = (uint)(FLOAT_803e02e0 *
                              (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390));
            local_90 = (double)(longlong)(int)local_108;
            local_cc = (undefined *)0x110214;
            local_ce = 0x30;
          }
          else if (iVar8 < 0xf) {
            if (iVar8 == 0xd) {
              local_d4 = FLOAT_803e0170;
              local_108 = 0x8a;
              local_cc = (undefined *)0x10000;
              local_ce = 0x30;
            }
            else if (iVar8 < 0xd) {
              local_d4 = FLOAT_803e0170;
              local_108 = 0x8a;
              local_cc = (undefined *)0x10000;
              local_ce = 0x30;
            }
            else {
              local_dc = FLOAT_803e0284;
              local_d4 = FLOAT_803e0170;
              local_108 = 0x8a;
              local_cc = (undefined *)0x10002;
              local_ce = 0x30;
            }
          }
          else if (iVar8 < 0x11) {
            uVar7 = FUN_80022264(0,0x28);
            local_78 = (double)CONCAT44(0x43300000,0x14 - uVar7 ^ 0x80000000);
            local_dc = (float)(local_78 - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0,0xa0);
            uStack_7c = 0x50 - uVar7 ^ 0x80000000;
            local_80 = 0x43300000;
            local_ec = FLOAT_803e0164 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0,0xa0);
            uStack_84 = 0x50 - uVar7 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803e0164 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_d4 = FLOAT_803e0160;
            uVar7 = FUN_80022264(0,3);
            local_90 = (double)CONCAT44(0x43300000,uVar7 + 1 ^ 0x80000000);
            local_108 = (uint)(FLOAT_803e0344 * (float)(local_90 - DOUBLE_803e0390));
            local_98 = (double)(longlong)(int)local_108;
            local_cc = (undefined *)0x110204;
            local_ce = 0x30;
          }
          else {
            uVar7 = FUN_80022264(0,0xa0);
            local_78 = (double)CONCAT44(0x43300000,0x50 - uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e0164 * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0,0x50);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e0288 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0,0xa0);
            uStack_84 = 0x50 - uVar7 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803e0164 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_d4 = FLOAT_803e0160;
            uVar7 = FUN_80022264(0,3);
            local_90 = (double)CONCAT44(0x43300000,uVar7 + 1 ^ 0x80000000);
            local_108 = (uint)(FLOAT_803e02e0 * (float)(local_90 - DOUBLE_803e0390));
            local_98 = (double)(longlong)(int)local_108;
            local_cc = (undefined *)0x1110214;
            local_ce = 0x33;
          }
        }
        else if (iVar8 == 0x19) {
          uVar7 = FUN_80022264(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803e0168 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffff6,10);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = FLOAT_803e0168 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xfffffff6,10);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = FLOAT_803e0168 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          local_d4 = FLOAT_803e0148;
          local_108 = 0x32;
          local_cc = (undefined *)0x211;
          local_ce = 0x30;
        }
        else if (iVar8 < 0x19) {
          if (iVar8 == 0x14) {
            local_d4 = FLOAT_803e01b0;
            local_108 = 0xd;
            local_cc = (undefined *)0x110212;
            local_ce = 0x33;
          }
          else {
            if (0x13 < iVar8) goto LAB_800aee9c;
            local_d4 = FLOAT_803e0340;
            local_108 = 0xd05;
            local_b0 = 0;
            local_cc = (undefined *)0x11;
            local_ce = 0x30;
          }
        }
        else {
          uVar7 = FUN_80022264(0,0x14);
          local_78 = (double)CONCAT44(0x43300000,10 - uVar7 ^ 0x80000000);
          local_ec = FLOAT_803e0170 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0,0x3c);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = FLOAT_803e0170 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,0x14);
          uStack_84 = 10 - uVar7 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = FLOAT_803e0170 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,4);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0310 * (float)(local_90 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,3);
          local_98 = (double)CONCAT44(0x43300000,uVar7 + 1 ^ 0x80000000);
          local_108 = (uint)(FLOAT_803e031c * (float)(local_98 - DOUBLE_803e0390));
          local_a0 = (double)(longlong)(int)local_108;
          local_cc = (undefined *)0x1000211;
          local_ce = 0x30;
        }
      }
      else if (iVar8 == 0x28) {
        local_d4 = FLOAT_803e014c;
        local_108 = 0x46;
        local_cc = (undefined *)0xb100200;
        local_ce = 0x74;
      }
      else if (iVar8 < 0x28) {
        if (iVar8 == 0x22) {
          local_d8 = FLOAT_803e017c;
          local_d4 = FLOAT_803e0148;
          local_108 = 0x178e;
          local_b0 = 0xff;
          local_af = 0x10;
          local_cc = (undefined *)0x14;
          local_ce = 0x30;
        }
        else if (iVar8 < 0x22) {
          if (iVar8 == 0x1f) {
            uVar7 = FUN_80022264(2,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e0170 * (float)(local_78 - DOUBLE_803e0390);
            local_108 = 200;
            local_cc = (undefined *)0xa100201;
            local_ce = 0x56;
          }
          else if (iVar8 < 0x1f) {
            if (iVar8 == 0x1d) {
              local_dc = FLOAT_803e0334;
              local_d8 = FLOAT_803e0338;
              uVar7 = FUN_80022264(0,0x14);
              local_78 = (double)CONCAT44(0x43300000,10 - uVar7 ^ 0x80000000);
              local_ec = FLOAT_803e030c * (float)(local_78 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0,0x14);
              uStack_7c = 10 - uVar7 ^ 0x80000000;
              local_80 = 0x43300000;
              local_e8 = FLOAT_803e030c *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              local_d4 = FLOAT_803e033c;
              local_108 = 0x78;
              local_cc = (undefined *)0x204;
              local_ce = 0x1f0;
            }
            else if (iVar8 < 0x1d) {
              uVar7 = FUN_80022264(0xffffff38,200);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803e0390);
              local_dc = FLOAT_803e032c;
              uStack_7c = FUN_80022264(0xffffff38,200);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0,0x14);
              uStack_84 = 10 - uVar7 ^ 0x80000000;
              local_88 = 0x43300000;
              local_ec = FLOAT_803e016c *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0,0x14);
              local_90 = (double)CONCAT44(0x43300000,10 - uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803e016c * (float)(local_90 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0,0x14);
              local_98 = (double)CONCAT44(0x43300000,10 - uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803e030c * (float)(local_98 - DOUBLE_803e0390);
              local_d4 = FLOAT_803e0330;
              local_108 = 0x104;
              local_cc = (undefined *)0x1000202;
              local_10c = 0x1e;
              local_e0 = FLOAT_803e015c;
              local_dc = FLOAT_803e01c0;
              local_d8 = FLOAT_803e015c;
              uVar7 = FUN_80022264(0,0x14);
              local_a0 = (double)CONCAT44(0x43300000,10 - uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803e016c * (float)(local_a0 - DOUBLE_803e0390);
              local_d4 = FLOAT_803e0280;
              local_108 = 0xa0;
              local_cc = (undefined *)0x11000204;
              local_ce = 0x151;
            }
            else {
              uVar7 = FUN_80022264(1,4);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e0234 * (float)(local_78 - DOUBLE_803e0390);
              local_108 = 0x5a;
              local_b0 = 0xff;
              local_cc = (undefined *)0xa100100;
              local_ce = 0x56;
              local_af = 0;
            }
          }
          else if (iVar8 < 0x21) {
            local_dc = FLOAT_803e0238;
            local_d4 = FLOAT_803e02ac;
            local_108 = 200;
            local_b0 = 0x9b;
            local_cc = (undefined *)0x12;
            local_ce = 0x22d;
          }
          else {
            uVar7 = FUN_80022264(0,0x14);
            local_78 = (double)CONCAT44(0x43300000,10 - uVar7 ^ 0x80000000);
            local_e0 = (float)(local_78 - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0,0x14);
            uStack_7c = 10 - uVar7 ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            local_ec = FLOAT_803e02a8;
            local_e8 = FLOAT_803e0324;
            local_e4 = FLOAT_803e02a8;
            local_d4 = FLOAT_803e02ac;
            local_108 = 0x32;
            local_cc = (undefined *)0x201;
            local_ce = 0x321;
          }
        }
        else if (iVar8 == 0x25) {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          if (param_3 == (short *)0x0) goto LAB_800aee9c;
          uVar7 = FUN_80022264(0,6);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = *(float *)(param_3 + 6) + (float)(local_78 - DOUBLE_803e0390);
          local_dc = *(float *)(param_3 + 8);
          uStack_7c = FUN_80022264(0,6);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = *(float *)(param_3 + 10) +
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0,10);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803e02b4 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(4,8);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0234 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = 0x24;
          local_b0 = 0x41;
          local_cc = (undefined *)0x100112;
          local_ce = 0x61;
        }
        else if (iVar8 < 0x25) {
          if (iVar8 < 0x24) {
            local_dc = FLOAT_803e0200;
            local_d4 = FLOAT_803e0328;
            local_108 = 0x69;
            local_cc = (undefined *)0x400010;
            local_ce = 0x4b;
          }
          else {
            local_d4 = FLOAT_803e0328;
            local_108 = 0x5f;
            local_cc = (undefined *)0x400212;
            local_ce = 0x4b;
          }
        }
        else if (iVar8 < 0x27) {
          uVar7 = FUN_80022264(0xffffffff,1);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803e0390);
          if (param_6 != (float *)0x0) {
            local_e0 = local_e0 + param_6[1];
          }
          local_dc = FLOAT_803e015c;
          uVar7 = FUN_80022264(0xffffffff,1);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = (float)(local_78 - DOUBLE_803e0390);
          local_e8 = FLOAT_803e0288;
          local_d4 = FLOAT_803e0160;
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
          local_11c = FLOAT_803e015c;
          local_118 = FLOAT_803e015c;
          local_114 = FLOAT_803e015c;
          local_120 = FLOAT_803e0150;
          local_124 = 0;
          local_126 = 0;
          local_128 = *puVar6;
          FUN_80021b8c(&local_128,&local_e0);
        }
        else {
          local_dc = FLOAT_803e0200;
          uVar7 = FUN_80022264(1,2);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e02a4 * (float)(local_78 - DOUBLE_803e0390);
          local_108 = 200;
          local_cc = (undefined *)0xa100201;
          local_ce = 0x6b;
        }
      }
      else if (iVar8 == 0x2e) {
        local_d4 = FLOAT_803e014c;
        local_108 = 0x30;
        local_af = 0;
        local_cc = (undefined *)0x8100210;
        local_ce = 0x5e;
      }
      else if (iVar8 < 0x2e) {
        if (iVar8 == 0x2b) {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
          }
          local_ec = FLOAT_803e0288;
          uVar7 = FUN_80022264(0,0xfffe);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          dVar10 = (double)(float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0,0xfffe);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          dVar11 = (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0,0xfffe);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_11c = FLOAT_803e015c;
          local_118 = FLOAT_803e015c;
          local_114 = FLOAT_803e015c;
          local_120 = FLOAT_803e0150;
          iVar1 = (int)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          local_90 = (double)(longlong)iVar1;
          local_124 = (ushort)iVar1;
          local_98 = (double)(longlong)(int)dVar11;
          local_126 = (ushort)(int)dVar11;
          local_a0 = (double)(longlong)(int)dVar10;
          local_128 = (ushort)(int)dVar10;
          FUN_80021b8c(&local_128,&local_ec);
          local_d4 = FLOAT_803e0310;
          local_108 = 0x32;
          local_d0 = 0;
          local_cc = (undefined *)0x100;
          local_ce = 0x30;
        }
        else if (iVar8 < 0x2b) {
          if (iVar8 < 0x2a) goto LAB_800aee9c;
          uVar7 = FUN_80022264(0xffffffe2,0x1e);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e014c * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xffffffe2,0x1e);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803e014c *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xffffffe2,0x1e);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803e014c *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,10);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0154 * (float)(local_90 - DOUBLE_803e0390) + FLOAT_803e02ac;
          local_108 = FUN_80022264(0x14,0x32);
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
        else if (iVar8 < 0x2d) {
          local_d4 = FLOAT_803e0168;
          local_108 = 10;
          local_af = 0;
          local_cc = (undefined *)0x80211;
          local_ce = 0x3ff;
        }
        else {
          local_dc = FLOAT_803e02c4;
          uVar7 = FUN_80022264(0,0xa0);
          local_78 = (double)CONCAT44(0x43300000,0x50 - uVar7 ^ 0x80000000);
          local_ec = FLOAT_803e0168 * (float)(local_78 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,0xa0);
          uStack_7c = 0x50 - uVar7 ^ 0x80000000;
          local_80 = 0x43300000;
          local_e4 = FLOAT_803e0168 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          local_d4 = FLOAT_803e0280;
          uStack_84 = FUN_80022264(1,4);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_108 = (uint)(FLOAT_803e02e0 *
                            (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390));
          local_90 = (double)(longlong)(int)local_108;
          local_cc = (undefined *)0x100000;
          local_ce = 0x30;
        }
      }
      else if (iVar8 == 0x31) {
        local_d4 = FLOAT_803e0314;
        local_108 = 0x46;
        local_af = 0;
        local_cc = (undefined *)0xb100200;
        local_ce = 0x74;
      }
      else if (iVar8 < 0x31) {
        if (iVar8 < 0x30) {
          local_d4 = FLOAT_803e0288;
          local_108 = 0x32;
          local_af = 0x20;
          local_cc = (undefined *)0x400010;
          local_ce = 0x71;
        }
        else {
          local_d4 = FLOAT_803e0150;
          local_108 = 0x14;
          local_cc = (undefined *)0x400010;
          local_ce = 0x7c;
        }
      }
      else if (iVar8 < 0x33) {
        local_d4 = FLOAT_803e0260;
        local_108 = 0x96;
        local_cc = (undefined *)0x400012;
        local_ce = 0x7c;
      }
      else {
        local_dc = FLOAT_803e02c4;
        local_d4 = FLOAT_803e02ac;
        local_108 = 0x55;
        local_cc = (undefined *)0x400012;
        local_ce = 0x7c;
      }
    }
    else if (iVar8 == 0x51) {
      local_d4 = FLOAT_803e0148;
      local_108 = 10;
      local_cc = (undefined *)0x200;
      local_ce = 0x2b;
    }
    else if (iVar8 < 0x51) {
      if (iVar8 == 0x42) {
        uVar7 = FUN_80022264(0,4);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = FLOAT_803e0178 - (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0,4);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = FLOAT_803e0178 -
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uStack_84 = FUN_80022264(0,4);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = FLOAT_803e0178 -
                   (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
        local_d4 = FLOAT_803e01e8;
        local_108 = 1;
        local_cc = (undefined *)0x70800;
        uVar7 = FUN_80022264(0,1);
        local_ce = (short)uVar7 + 0xdd;
        local_f8 = FLOAT_803e015c;
        local_f4 = FLOAT_803e015c;
        local_f0 = FLOAT_803e015c;
        local_fc = FLOAT_803e0150;
        uVar7 = FUN_80022264(0,1000);
        local_100 = 500 - (short)uVar7;
        uVar7 = FUN_80022264(0,1000);
        local_102 = 500 - (short)uVar7;
        uVar7 = FUN_80022264(0,1000);
        local_104 = 500 - (short)uVar7;
      }
      else if (iVar8 < 0x42) {
        if (iVar8 == 0x3a) {
          uVar7 = FUN_80022264(0,0x3c);
          local_78 = (double)CONCAT44(0x43300000,0x1e - uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e02e4 * (float)(local_78 - DOUBLE_803e0390);
          local_dc = FLOAT_803e0200;
          uVar7 = FUN_80022264(0,0x3c);
          uStack_7c = 0x1e - uVar7 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803e02e4 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0x28,0x50);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803e02ec *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e02f0 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = 0xb4;
          local_af = 0;
          local_cc = (undefined *)0x80400200;
          local_ce = 0x47;
        }
        else if (iVar8 < 0x3a) {
          if (iVar8 == 0x37) {
            local_d4 = FLOAT_803e0164;
            local_108 = 0x14;
            local_d0 = 0x9a;
            local_cc = (undefined *)0x100210;
            local_ce = 0x87;
          }
          else if (iVar8 < 0x37) {
            if (iVar8 < 0x36) {
              uVar7 = FUN_80022264(0,0x3c);
              local_78 = (double)CONCAT44(0x43300000,0x1e - uVar7 ^ 0x80000000);
              local_e0 = FLOAT_803e02e4 * (float)(local_78 - DOUBLE_803e0390);
              local_dc = FLOAT_803e02e8;
              uVar7 = FUN_80022264(0,0x3c);
              uStack_7c = 0x1e - uVar7 ^ 0x80000000;
              local_80 = 0x43300000;
              local_d8 = FLOAT_803e02e4 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0x28,0x50);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e8 = FLOAT_803e02ec *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0x28,0x50);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e02f0 * (float)(local_90 - DOUBLE_803e0390);
              local_108 = FUN_80022264(0x28,0x50);
              local_af = 0;
              local_cc = (undefined *)0x80400001;
              local_ce = 0x47;
            }
            else {
              if (param_6 == (float *)0x0) goto LAB_800aee9c;
              local_d4 = FLOAT_803e01e8;
              local_108 = 0x20;
              local_b0 = 0xff;
              local_af = 0x20;
              local_cc = (undefined *)0x1100201;
              local_ce = 0x249;
            }
          }
          else if (iVar8 < 0x39) {
            FUN_80293544(0x4233d);
            dVar11 = (double)FLOAT_803e02c4;
            dVar12 = (double)FLOAT_803e0168;
            dVar13 = (double)FLOAT_803e0280;
            dVar14 = (double)FLOAT_803e02e0;
            dVar10 = DOUBLE_803e0390;
            for (sVar9 = 0; sVar9 < 0x28; sVar9 = sVar9 + 1) {
              local_dc = (float)dVar11;
              uVar7 = FUN_80022264(0,0xa0);
              local_78 = (double)CONCAT44(0x43300000,0x50 - uVar7 ^ 0x80000000);
              local_ec = (float)(dVar12 * (double)(float)(local_78 - dVar10));
              uVar7 = FUN_80022264(0,0xa0);
              uStack_7c = 0x50 - uVar7 ^ 0x80000000;
              local_80 = 0x43300000;
              local_e4 = (float)(dVar12 * (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                         dVar10));
              local_d4 = (float)dVar13;
              uStack_84 = FUN_80022264(1,4);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_108 = (uint)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack_84) -
                                                         dVar10));
              local_90 = (double)(longlong)(int)local_108;
              local_cc = (undefined *)0x100011;
              local_ce = 0x30;
              fVar2 = local_f8;
              fVar3 = local_f4;
              fVar4 = local_f0;
              if (local_110 != (ushort *)0x0) {
                fVar2 = *(float *)(local_110 + 6);
                fVar3 = *(float *)(local_110 + 8);
                fVar4 = *(float *)(local_110 + 10);
              }
              local_d8 = local_d8 + fVar4;
              local_dc = local_dc + fVar3;
              local_e0 = local_e0 + fVar2;
              (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
            }
          }
          else {
            uVar7 = FUN_80022264(0,1);
            if (uVar7 == 0) {
              local_d8 = FLOAT_803e02fc;
            }
            else {
              local_d8 = FLOAT_803e01dc;
            }
            uVar7 = FUN_80022264(1,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e0300 * (float)(local_78 - DOUBLE_803e0390);
            local_108 = FUN_80022264(0,0x18);
            local_108 = local_108 + 0x18;
            local_b0 = 0xff;
            local_cc = (undefined *)0x100;
            local_ce = 0x33;
          }
        }
        else if (iVar8 == 0x40) {
          uVar7 = FUN_80022264(0,0x28);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_dc = (float)(local_78 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,2);
          uStack_7c = 1 - uVar7 ^ 0x80000000;
          local_80 = 0x43300000;
          local_ec = FLOAT_803e02b8 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(1,3);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803e02b8 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,2);
          local_90 = (double)CONCAT44(0x43300000,1 - uVar7 ^ 0x80000000);
          local_e4 = FLOAT_803e02b8 * (float)(local_90 - DOUBLE_803e0390);
          local_d4 = FLOAT_803e024c;
          local_108 = 0x96;
          local_cc = (undefined *)0x108;
          local_ce = 0x5c;
        }
        else if (iVar8 < 0x40) {
          if (iVar8 == 0x3c) {
            local_dc = FLOAT_803e0230;
            uVar7 = FUN_80022264(1,10);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e0234 * (float)(local_78 - DOUBLE_803e0390) + FLOAT_803e01d0;
            local_b0 = 0xff;
            uVar7 = FUN_80022264(0,0xffff);
            local_104 = (short)uVar7;
            uVar7 = FUN_80022264(0,0xffff);
            local_102 = (short)uVar7;
            uVar7 = FUN_80022264(0,0xffff);
            local_104 = (short)uVar7;
            local_f8 = FLOAT_803e015c;
            local_f4 = FLOAT_803e015c;
            local_f0 = FLOAT_803e015c;
            local_108 = FUN_80022264(0,0x14);
            local_108 = local_108 + 0x28;
            local_af = 0x10;
            local_cc = (undefined *)0x6100214;
            local_ce = 0xc79;
          }
          else {
            if (0x3b < iVar8) goto LAB_800aab38;
            uVar7 = FUN_80022264(0,0x3c);
            local_78 = (double)CONCAT44(0x43300000,0x1e - uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803e02a4 * (float)(local_78 - DOUBLE_803e0390);
            local_dc = FLOAT_803e0284;
            uVar7 = FUN_80022264(0,0x3c);
            uStack_7c = 0x1e - uVar7 ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = FLOAT_803e02a4 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0x28,0x50);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e8 = FLOAT_803e02ec *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0x28,0x50);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e02f0 * (float)(local_90 - DOUBLE_803e0390);
            local_108 = 0x78;
            local_af = 0;
            local_cc = (undefined *)0x80400201;
            local_ce = 0x47;
          }
        }
        else {
          dVar14 = (double)FLOAT_803e02bc;
          dVar13 = (double)FLOAT_803e02c0;
          dVar12 = (double)FLOAT_803e02b8;
          dVar11 = (double)FLOAT_803e0234;
          dVar10 = DOUBLE_803e0390;
          for (sVar9 = 0; sVar9 < 0x1e; sVar9 = sVar9 + 1) {
            local_dc = (float)dVar14;
            uVar7 = FUN_80022264(0,4);
            local_78 = (double)CONCAT44(0x43300000,2 - uVar7 ^ 0x80000000);
            local_ec = (float)(dVar13 * (double)(float)(local_78 - dVar10));
            uStack_7c = FUN_80022264(1,2);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = (float)(dVar12 * (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                       dVar10));
            uVar7 = FUN_80022264(0,4);
            uStack_84 = 2 - uVar7 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_84) -
                                                       dVar10));
            local_d4 = (float)dVar11;
            local_108 = 0x3c;
            local_cc = (undefined *)0x108;
            local_ce = 0x5c;
            (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
          }
        }
      }
      else if (iVar8 == 0x4b) {
        local_d4 = FLOAT_803e022c;
        local_108 = 0x14;
        local_af = 0;
        local_cc = (undefined *)0x80100;
        local_ce = 0xdf;
      }
      else if (iVar8 < 0x4b) {
        if (iVar8 == 0x48) {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
          }
          uVar7 = FUN_80022264(1,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e8 = FLOAT_803e0188 * (float)(local_78 - DOUBLE_803e0390);
          local_11c = FLOAT_803e015c;
          local_118 = FLOAT_803e015c;
          local_114 = FLOAT_803e015c;
          local_120 = FLOAT_803e01b0;
          uVar7 = FUN_80022264(0,4000);
          local_124 = 2000 - (short)uVar7;
          uVar7 = FUN_80022264(0,4000);
          local_126 = 2000 - (short)uVar7;
          uVar7 = FUN_80022264(0,4000);
          local_128 = 2000 - (short)uVar7;
          FUN_80021b8c(&local_128,&local_ec);
          local_d4 = FLOAT_803e02dc;
          local_108 = 0x50;
          local_af = 8;
          local_cc = (undefined *)0x100;
          local_ce = 0xdd;
        }
        else if (iVar8 < 0x48) {
          if (iVar8 < 0x47) {
            if (0x44 < iVar8) goto LAB_800aee9c;
LAB_800aab38:
            local_cc = (undefined *)0x20100100;
            local_108 = 400;
            if (iVar8 == 0x3d) {
              uVar7 = FUN_80022264(0,0x14);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = FLOAT_803e0200 - (float)(local_78 - DOUBLE_803e0390);
              local_dc = FLOAT_803e02c4;
              uStack_7c = FUN_80022264(0,0x14);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_d8 = FLOAT_803e0200 -
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(1,3);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d4 = FLOAT_803e016c *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              local_c8 = local_c8 | 0x1000000;
            }
            else if (iVar8 == 0x3e) {
              uVar7 = FUN_80022264(0,0x14);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = FLOAT_803e0200 - (float)(local_78 - DOUBLE_803e0390);
              local_dc = FLOAT_803e02c8;
              uStack_7c = FUN_80022264(0,0x14);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_d8 = FLOAT_803e0200 -
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(1,3);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d4 = FLOAT_803e02a4 *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              local_c8 = local_c8 | 0x1000000;
            }
            else if (iVar8 == 0x3f) {
              local_dc = FLOAT_803e02cc;
              local_108 = 100;
              uVar7 = FUN_80022264(1,3);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e02a4 * (float)(local_78 - DOUBLE_803e0390);
              local_c8 = local_c8 | 0x1000000;
            }
            else if (iVar8 == 0x43) {
              local_e0 = FLOAT_803e02d0;
              local_dc = FLOAT_803e01b8;
              uVar7 = FUN_80022264(0,0x78);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d8 = FLOAT_803e01e4 + (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(1,8);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_d4 = FLOAT_803e0168 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              local_cc = (undefined *)((uint)local_cc | 8);
              local_c8 = local_c8 | 0x1000000;
            }
            else if (iVar8 == 0x44) {
              local_e0 = FLOAT_803e02d0;
              local_dc = FLOAT_803e02d4;
              uVar7 = FUN_80022264(0,0x78);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d8 = (float)(local_78 - DOUBLE_803e0390);
              local_e8 = FLOAT_803e02d8;
              uStack_7c = FUN_80022264(1,8);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_d4 = FLOAT_803e0168 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              local_c8 = local_c8 | 0x1000000;
            }
            local_af = 0x20;
            local_ce = 0x5f;
            local_cc = (undefined *)((uint)local_cc | param_4);
            if (((uint)local_cc & 1) != 0) {
              if (local_110 == (ushort *)0x0) {
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
            if ((iVar8 == 0x3e) || (iVar8 == 0x3f)) {
              local_cc = (undefined *)((uint)local_cc | 0x8000000);
            }
          }
          else {
            uVar7 = FUN_80022264(0,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803e0178 - (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0,4);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_dc = FLOAT_803e0178 -
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0,4);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_d8 = FLOAT_803e0178 -
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_d4 = FLOAT_803e0184;
            local_108 = FUN_80022264(4,0xe);
            local_cc = (undefined *)0x110100;
            local_ce = 0xc22;
          }
        }
        else if (iVar8 < 0x4a) {
          local_dc = FLOAT_803e0284;
          local_d4 = FLOAT_803e01b0;
          local_108 = 0xe;
          local_b0 = 0;
          local_cc = (undefined *)0x110210;
          local_ce = 0x31;
        }
        else {
          local_dc = FLOAT_803e02b0;
          local_d4 = FLOAT_803e02b4;
          local_108 = 0x78;
          local_af = 0;
          local_10c = 0x4b;
          local_cc = (undefined *)0x70000;
          uVar7 = FUN_80022264(0,3);
          local_ce = (short)uVar7 + 0xdd;
          local_f8 = FLOAT_803e015c;
          local_f4 = FLOAT_803e017c;
          local_f0 = FLOAT_803e015c;
          local_fc = FLOAT_803e0150;
          local_100 = 0;
          uVar7 = FUN_80022264(0,1000);
          local_102 = 500 - (short)uVar7;
          uVar7 = FUN_80022264(0,1000);
          local_104 = 500 - (short)uVar7;
        }
      }
      else if (iVar8 == 0x4e) {
        uVar7 = FUN_80022264(0,2);
        local_78 = (double)CONCAT44(0x43300000,1 - uVar7 ^ 0x80000000);
        local_ec = FLOAT_803e02a8 * (float)(local_78 - DOUBLE_803e0390);
        uVar7 = FUN_80022264(0,2);
        uStack_7c = 1 - uVar7 ^ 0x80000000;
        local_80 = 0x43300000;
        local_e4 = FLOAT_803e02a8 *
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        local_d4 = FLOAT_803e02ac;
        local_108 = 0x4b;
        local_af = 0;
        local_cc = (undefined *)0x200;
        local_ce = 0x7b;
      }
      else if (iVar8 < 0x4e) {
        if (iVar8 < 0x4d) goto LAB_800aee9c;
        local_dc = FLOAT_803e02a0;
        local_d4 = FLOAT_803e02a4;
        local_108 = 400;
        local_af = 0;
        local_10c = 0x4e;
        local_cc = (undefined *)0x20100;
        local_ce = 0xdf;
        local_f8 = FLOAT_803e015c;
        local_f4 = FLOAT_803e015c;
        local_f0 = FLOAT_803e015c;
        local_fc = FLOAT_803e0150;
        uVar7 = FUN_80022264(0,200);
        local_100 = 100 - (short)uVar7;
        uVar7 = FUN_80022264(0,200);
        local_102 = 100 - (short)uVar7;
        uVar7 = FUN_80022264(0,200);
        local_104 = 100 - (short)uVar7;
      }
      else {
        if (iVar8 < 0x50) goto LAB_800aab38;
        local_d4 = FLOAT_803e024c;
        local_108 = 10;
        local_cc = (undefined *)0x200;
        local_ce = 0x2b;
      }
    }
    else if (iVar8 == 0x60) {
      uStack_a4 = FUN_80022264(0xfffffff6,10);
      uStack_a4 = uStack_a4 ^ 0x80000000;
      local_a8 = 0x43300000;
      local_e0 = (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xfffffff6,10);
      local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_dc = (float)(local_a0 - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xfffffff6,10);
      local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_d8 = (float)(local_98 - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xffffffce,0x32);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_ec = FLOAT_803e0164 * (float)(local_90 - DOUBLE_803e0390);
      uStack_84 = FUN_80022264(0xffffffce,0x32);
      uStack_84 = uStack_84 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e8 = FLOAT_803e0164 * (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
      uStack_7c = FUN_80022264(0xffffffce,0x32);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      local_e4 = FLOAT_803e0164 * (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0x32,100);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_d4 = FLOAT_803e0148 * (float)(local_78 - DOUBLE_803e0390);
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
    else if (iVar8 < 0x60) {
      if (iVar8 == 0x57) {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
          param_3 = &DAT_8039cf68;
        }
        uVar7 = FUN_80022264(0,10);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_dc = (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0xffffff9c,100);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_ec = *(float *)(param_3 + 4) *
                   FLOAT_803e0234 *
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uStack_84 = FUN_80022264(200,400);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        local_e8 = *(float *)(param_3 + 4) *
                   FLOAT_803e0234 *
                   (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
        uVar7 = FUN_80022264(0xffffff9c,100);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e4 = *(float *)(param_3 + 4) * FLOAT_803e0234 * (float)(local_90 - DOUBLE_803e0390);
        uVar7 = FUN_80022264(8,0xb);
        local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = *(float *)(param_3 + 4) * FLOAT_803e01a4 * (float)(local_98 - DOUBLE_803e0390);
        local_b0 = 0xbe;
        local_108 = (uint)(FLOAT_803e0348 * *(float *)(param_3 + 4));
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
      else if (iVar8 < 0x57) {
        if (iVar8 == 0x54) {
          uVar7 = FUN_80022264(0,10);
          local_78 = (double)CONCAT44(0x43300000,5 - uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,10);
          uStack_7c = 5 - uVar7 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(2,0xc);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d4 = FLOAT_803e024c *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          local_108 = 0x78;
          local_cc = (undefined *)0xa100201;
          local_ce = 0x56;
        }
        else if (iVar8 < 0x54) {
          if (iVar8 < 0x53) goto LAB_800aee9c;
          uVar7 = FUN_80022264(0,0x3c);
          local_78 = (double)CONCAT44(0x43300000,0x1e - uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e02e4 * (float)(local_78 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,0x3c);
          uStack_7c = 0x1e - uVar7 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803e02e4 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0x28,0x50);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803e0194 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e02f0 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = 0xd2;
          local_cc = &DAT_80000201;
          uVar7 = FUN_80022264(0,3);
          local_ce = (short)uVar7 + 0xdd;
        }
        else if (iVar8 < 0x56) {
          local_d4 = FLOAT_803e0168;
          local_108 = 0x78;
          local_b0 = 0xff;
          local_af = 0x20;
          local_cc = (undefined *)0xa100201;
          local_ce = 0x56;
        }
        else {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          uVar7 = FUN_80022264(0xfffffffa,6);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffffa,6);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xfffffffe,2);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_ec = *(float *)(param_3 + 4) *
                     FLOAT_803e0188 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,4);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e8 = *(float *)(param_3 + 4) * FLOAT_803e014c * (float)(local_90 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0xfffffffe,2);
          local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e4 = *(float *)(param_3 + 4) * FLOAT_803e0188 * (float)(local_98 - DOUBLE_803e0390);
          local_d4 = FLOAT_803e02b4 * *(float *)(param_3 + 4);
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
      else if (iVar8 == 0x5e) {
        uStack_a4 = FUN_80022264(0x14,0x1e);
        uStack_a4 = uStack_a4 ^ 0x80000000;
        local_a8 = 0x43300000;
        local_d4 = FLOAT_803e0148 *
                   (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e0390);
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
      else if (iVar8 < 0x5e) {
        if (iVar8 == 0x59) {
          uVar7 = FUN_80022264(0,4);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803e0178 - (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0,4);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = FLOAT_803e0178 -
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0,4);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = FLOAT_803e0178 -
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(1,0x28);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a4 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = 0x28;
          local_cc = (undefined *)0x200;
          local_ce = 0x2b;
        }
        else {
          if (0x58 < iVar8) goto LAB_800aee9c;
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          uVar7 = FUN_80022264(0xffffff9c,100);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = *(float *)(param_3 + 4) * FLOAT_803e0170 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(10,200);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_e8 = *(float *)(param_3 + 4) *
                     FLOAT_803e0170 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xffffff9c,100);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e4 = *(float *)(param_3 + 4) *
                     FLOAT_803e0170 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(8,0xb);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = *(float *)(param_3 + 4) * FLOAT_803e01a4 * (float)(local_90 - DOUBLE_803e0390);
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
        local_d4 = FLOAT_803e0160;
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
    else if (iVar8 == 0x6a) {
      uVar7 = FUN_80022264(0xfffffff6,10);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = FLOAT_803e0150 * (float)(local_78 - DOUBLE_803e0390);
      local_dc = FLOAT_803e015c;
      uStack_7c = FUN_80022264(0xfffffff6,10);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      local_d8 = FLOAT_803e0150 * (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
      local_ec = FLOAT_803e015c;
      uStack_84 = FUN_80022264(1,3);
      uStack_84 = uStack_84 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e8 = FLOAT_803e0254 * (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
      local_e4 = FLOAT_803e015c;
      local_d4 = FLOAT_803e0170;
      local_108 = 0x78;
      local_b0 = 0xff;
      local_af = 0x10;
      local_cc = (undefined *)0x100200;
      local_ce = 0x5f;
    }
    else if (iVar8 < 0x6a) {
      if (iVar8 == 0x67) {
        local_d4 = FLOAT_803e0290;
        local_108 = 0x1e;
        local_b0 = 0xff;
        local_cc = (undefined *)0x200;
        uVar7 = FUN_80022264(0,2);
        local_ce = (short)uVar7 + 0x156;
      }
      else if (iVar8 < 0x67) {
        if (iVar8 == 0x65) {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          if (param_3 == (short *)0x0) goto LAB_800aee9c;
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          local_c4 = 0xffff;
          local_c0 = 0xffff;
          local_bc = 0xffff;
          local_b8 = 0;
          local_b6 = 0;
          local_b4 = 0;
          local_d4 = FLOAT_803e0218;
          local_108 = 100;
          local_b0 = 0xff;
          local_c8 = 0x20;
          local_ce = 0x30;
        }
        else {
          if (iVar8 < 0x65) goto LAB_800aee9c;
          local_af = 0x20;
          local_d4 = FLOAT_803e0290;
          local_108 = 0x50;
          local_10c = 0x67;
          local_cc = (undefined *)0x400000;
          local_ce = 0x156;
        }
      }
      else if (iVar8 < 0x69) {
        uVar7 = FUN_80022264(0xfffffff6,10);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_ec = FLOAT_803e026c * (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0xfffffff6,10);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_e8 = FLOAT_803e026c *
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uStack_84 = FUN_80022264(0xfffffff6,10);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        local_e4 = FLOAT_803e026c *
                   (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
        local_d4 = FLOAT_803e0294;
        local_108 = 0x69;
        local_cc = (undefined *)0x480200;
        local_ce = 0x156;
      }
      else {
        local_d4 = FLOAT_803e0308;
        local_108 = 0x44;
        local_cc = (undefined *)0x100201;
        local_ce = 0x60;
      }
    }
    else if (iVar8 == 0x6d) {
      if (param_3 == (short *)0x0) {
        DAT_8039cf74 = FLOAT_803e015c;
        DAT_8039cf78 = FLOAT_803e015c;
        DAT_8039cf7c = FLOAT_803e015c;
        DAT_8039cf70 = FLOAT_803e0150;
        DAT_8039cf68 = 0;
        DAT_8039cf6a = 0;
        DAT_8039cf6c = 0;
        DAT_8039cf6e = 0;
        param_3 = &DAT_8039cf68;
      }
      if (param_3 == (short *)0x0) goto LAB_800aee9c;
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
    else if (iVar8 < 0x6d) {
      if (iVar8 < 0x6c) {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
          param_3 = &DAT_8039cf68;
        }
        if (param_6 == (float *)0x0) goto LAB_800aee9c;
        local_e0 = *(float *)(param_3 + 6);
        local_dc = *(float *)(param_3 + 8);
        local_d8 = *(float *)(param_3 + 10);
        local_ec = *param_6;
        local_e8 = param_6[1];
        local_e4 = param_6[2];
        local_d4 = FLOAT_803e0148;
        local_108 = 0x28;
        local_78 = (double)(longlong)(int)*(float *)(param_3 + 4);
        local_b0 = (undefined)(int)*(float *)(param_3 + 4);
        local_af = 10;
        local_cc = (undefined *)0x200;
        local_ce = 0xc13;
        local_f8 = FLOAT_803e015c;
        local_f4 = FLOAT_803e015c;
        local_f0 = FLOAT_803e015c;
        local_fc = FLOAT_803e0150;
        local_100 = 0;
        local_102 = 0;
        local_104 = *param_3;
      }
      else {
        local_d4 = FLOAT_803e01e8;
        local_108 = 1;
        local_af = 0;
        local_cc = (undefined *)0x11;
        local_c8 = 2;
        local_ce = 0xdd;
      }
    }
    else {
      if (iVar8 < 0x71) goto LAB_800aee9c;
      uVar7 = FUN_80022264(0xfffffffe,2);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = (float)(local_78 - DOUBLE_803e0390);
      local_dc = FLOAT_803e0284;
      uStack_7c = FUN_80022264(0xfffffff0,0x10);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
      uStack_84 = FUN_80022264(0xfffffffd,0xffffffff);
      uStack_84 = uStack_84 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e8 = FLOAT_803e0288 * (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
      uVar7 = FUN_80022264(1,3);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_d4 = FLOAT_803e028c * (float)(local_90 - DOUBLE_803e0390);
      local_108 = 100;
      local_b0 = 0x7d;
      local_af = 0x10;
      local_cc = &DAT_80000100;
      local_ce = 0x2c;
    }
  }
  else {
    if (iVar8 == 0x52e) goto LAB_800aee9c;
    if (iVar8 < 0x52e) {
      if (iVar8 == 0x325) {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
        }
        local_d8 = FLOAT_803e0364;
        local_11c = FLOAT_803e015c;
        local_118 = FLOAT_803e015c;
        local_114 = FLOAT_803e015c;
        local_120 = FLOAT_803e0150;
        uVar7 = FUN_80022264(0xffff8001,0x7fff);
        local_124 = (ushort)uVar7;
        uVar7 = FUN_80022264(0xffff8001,0x7fff);
        local_126 = (ushort)uVar7;
        uVar7 = FUN_80022264(0xffff8001,0x7fff);
        local_128 = (ushort)uVar7;
        FUN_80021b8c(&local_128,&local_e0);
        local_ec = -(local_e0 / FLOAT_803e017c);
        local_e8 = -(local_dc / FLOAT_803e017c);
        local_e4 = -(local_d8 / FLOAT_803e017c);
        uVar7 = FUN_80022264(0x9e,0x240);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803e0368 * (float)(local_78 - DOUBLE_803e0390);
        local_108 = FUN_80022264(7,0x12);
        local_108 = local_108 + 0xc;
        local_ce = 0xc98;
        local_cc = (undefined *)0x480110;
        if (param_6 != (float *)0x0) {
          cVar5 = *(char *)param_6;
          if (cVar5 == '\x01') {
            local_c4 = 0x2898;
            local_c0 = 0xffff;
            local_bc = 0xffff;
            local_b8 = 0x6574;
            local_b6 = 0x9f9;
            local_b4 = 0xffff;
            local_c8 = local_c8 | 0x20;
          }
          else if (cVar5 == '\x02') {
            local_c4 = 0xff65;
            local_c0 = 0xd23c;
            local_bc = 0x7fff;
            local_b8 = 0xffc4;
            local_b6 = 0xdc81;
            local_b4 = 0x2603;
            local_c8 = local_c8 | 0x20;
            local_d4 = local_d4 * FLOAT_803e035c;
          }
          else if (cVar5 == '\x03') {
            local_c4 = 0xfebe;
            local_c0 = 0x5cb2;
            local_bc = 0xfd01;
            local_b8 = 0xfd2c;
            local_b6 = 0x8e5;
            local_b4 = 0x1f5;
            local_c8 = local_c8 | 0x20;
            local_d4 = local_d4 * FLOAT_803e036c;
          }
        }
      }
      else if (iVar8 < 0x325) {
        if (iVar8 == 0x7f) {
          local_d4 = FLOAT_803e026c;
          local_108 = 100;
          local_b0 = 0x37;
          local_cc = (undefined *)0x400100;
          if (local_100 == 1) {
            local_ce = 0x15f;
          }
          else if (local_100 < 1) {
            if (local_100 < 0) {
LAB_800a9838:
              local_ce = 0x15e;
            }
            else {
              local_ce = 0x15e;
            }
          }
          else {
            if (2 < local_100) goto LAB_800a9838;
            local_ce = 0x15d;
          }
          local_100 = 0;
        }
        else if (iVar8 < 0x7f) {
          if (iVar8 == 0x79) {
            uVar7 = FUN_80022264(0,1);
            if (uVar7 == 0) {
              local_e0 = FLOAT_803e0304;
            }
            else {
              local_e0 = FLOAT_803e02cc;
            }
            uVar7 = FUN_80022264(10,0x3c);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_dc = (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xfffffffd,3);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(1,0x14);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e8 = FLOAT_803e0168 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(1,7);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e0250 * (float)(local_90 - DOUBLE_803e0390);
            local_108 = FUN_80022264(0,0xf);
            local_108 = local_108 + 0xf;
            local_b0 = 0x9b;
            local_cc = (undefined *)0x100100;
            local_ce = 0x156;
          }
          else if (iVar8 < 0x79) {
            if (iVar8 == 0x76) {
              uVar7 = FUN_80022264(1,8);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e02f8 * (float)(local_78 - DOUBLE_803e0390);
              local_108 = FUN_80022264(0,0x32);
              local_108 = local_108 + 0x26;
              local_b0 = 0xff;
              local_f8 = FLOAT_803e015c;
              local_f4 = FLOAT_803e015c;
              local_f0 = FLOAT_803e015c;
              local_cc = (undefined *)0x6100110;
              local_ce = 0x159;
            }
            else if (iVar8 < 0x76) {
              if (iVar8 == 0x74) {
                uVar7 = FUN_80022264(0xffffffb0,0x50);
                local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_e0 = (float)(local_78 - DOUBLE_803e0390);
                local_dc = FLOAT_803e015c;
                uStack_7c = FUN_80022264(0xffffffb0,0x50);
                uStack_7c = uStack_7c ^ 0x80000000;
                local_80 = 0x43300000;
                local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
                uStack_84 = FUN_80022264(1,4);
                uStack_84 = uStack_84 ^ 0x80000000;
                local_88 = 0x43300000;
                local_e8 = FLOAT_803e014c *
                           (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
                local_d4 = FLOAT_803e022c;
                local_108 = 0x140;
                local_b0 = 0xff;
                local_cc = (undefined *)0x1000204;
                local_ce = 0x151;
              }
              else if (iVar8 < 0x74) {
                uVar7 = FUN_80022264(4,5);
                local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
                local_d4 = FLOAT_803e029c * (float)(local_78 - DOUBLE_803e0390) * FLOAT_803e01b0;
                local_108 = FUN_80022264(0x1e,0x28);
                local_cc = (undefined *)0x0;
                local_c8 = 2;
                local_af = 0x10;
                local_ce = 0xdf;
              }
              else {
                local_d4 = FLOAT_803e02b8;
                local_108 = 0x62;
                local_b0 = 0xff;
                local_d0 = 0xa9;
                local_af = 0;
                local_cc = (undefined *)0x8100210;
                local_ce = 0x159;
              }
            }
            else if (iVar8 < 0x78) {
              uVar7 = FUN_80022264(0xfffffffc,4);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0,0x28);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0xfffffffc,4);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0xffffffd8,0x28);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803e0280 * (float)(local_90 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0,0x50);
              local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803e02ec * (float)(local_98 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0xffffffd8,0x28);
              local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803e0280 * (float)(local_a0 - DOUBLE_803e0390);
              uStack_a4 = FUN_80022264(0x28,0x50);
              uStack_a4 = uStack_a4 ^ 0x80000000;
              local_a8 = 0x43300000;
              local_d4 = FLOAT_803e0220 *
                         (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e0390);
              local_108 = FUN_80022264(0,0x118);
              local_108 = local_108 + 0x96;
              local_b0 = 0xff;
              local_cc = (undefined *)0x400101;
              local_ce = 0xdf;
            }
            else {
              uVar7 = FUN_80022264(0,100);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_dc = (float)(local_78 - DOUBLE_803e0390);
              local_d4 = FLOAT_803e014c;
              local_108 = 0x30;
              local_af = 0;
              local_cc = (undefined *)0x8100210;
              local_ce = 0x5e;
            }
          }
          else if (iVar8 == 0x7c) {
            uVar7 = FUN_80022264(0xffffffe2,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = (float)(DOUBLE_803e0270 * (double)(float)(local_78 - DOUBLE_803e0390));
            uStack_7c = FUN_80022264(0xffffffe2,0x1e);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = (float)(DOUBLE_803e0270 *
                              (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                             DOUBLE_803e0390));
            local_d4 = FLOAT_803e0278;
            local_108 = 300;
            local_af = 0;
            local_cc = (undefined *)0x41001c;
            local_ce = 0xc13;
          }
          else if (iVar8 < 0x7c) {
            if (iVar8 < 0x7b) {
              uVar7 = FUN_80022264(0xfffffffc,4);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0,0x23);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0xfffffffc,4);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0xffffffd8,0x28);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803e0280 * (float)(local_90 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0xffffffd8,0x28);
              local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e4 = FLOAT_803e0280 * (float)(local_98 - DOUBLE_803e0390);
              uVar7 = FUN_80022264(0,0x50);
              local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e8 = FLOAT_803e0280 * (float)(local_a0 - DOUBLE_803e0390);
              uStack_a4 = FUN_80022264(0x28,0x50);
              uStack_a4 = uStack_a4 ^ 0x80000000;
              local_a8 = 0x43300000;
              local_d4 = FLOAT_803e0220 *
                         (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e0390);
              local_108 = FUN_80022264(0,0x118);
              local_108 = local_108 + 0xb4;
              local_b0 = 0;
              local_cc = (undefined *)0xc80404;
              local_ce = 0xdf;
            }
            else {
              uVar7 = FUN_80022264(0,10);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_dc = FLOAT_803e0264 + (float)(local_78 - DOUBLE_803e0390);
              local_e8 = FLOAT_803e0268;
              local_d4 = FLOAT_803e0188;
              local_108 = 0x50;
              local_af = 0;
              local_cc = (undefined *)0x8100208;
              local_ce = 0x91;
            }
          }
          else if (iVar8 < 0x7e) {
            local_d4 = FLOAT_803e01e8;
            local_108 = 0x14;
            local_af = 0;
            local_b0 = 0x32;
            local_cc = (undefined *)0x400100;
            local_ce = 0xc13;
          }
          else {
            local_108 = 0x32;
            local_cc = (undefined *)0x400100;
            uVar7 = FUN_80022264(0xfffffffc,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e016c * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xfffffffc,4);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = FLOAT_803e016c *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0x28,0x50);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e8 = FLOAT_803e0250 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0x28,0x50);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e027c * (float)(local_90 - DOUBLE_803e0390);
            if (local_100 == 1) {
              local_ce = 0x160;
            }
            else if (local_100 < 1) {
              if (local_100 < 0) {
LAB_800a9a54:
                local_ce = 0xdf;
              }
              else {
                local_ce = 0xdd;
              }
            }
            else {
              if (2 < local_100) goto LAB_800a9a54;
              local_ce = 0xdf;
            }
            local_100 = 0;
          }
        }
        else if (iVar8 < 0x2bf) {
          if (iVar8 == 0x83) {
            uVar7 = FUN_80022264(0xffffff60,0xa0);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xffffffce,0xfa);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0xffffff60,0xa0);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e0 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_d4 = FLOAT_803e0280;
            local_108 = 200;
            local_af = 0x10;
            local_cc = &DAT_80000108;
            local_ce = 0x167;
          }
          else if (iVar8 < 0x83) {
            if (iVar8 == 0x81) {
              uVar7 = FUN_80022264(0xffffff1a,0xe6);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0xffffffce,0xfa);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0xffffff1a,0xe6);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_d8 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              local_d4 = FLOAT_803e0280;
              local_108 = 200;
              local_af = 0x10;
              local_cc = &DAT_80000108;
              local_ce = 0x165;
            }
            else if (iVar8 < 0x81) {
              local_d4 = FLOAT_803e024c;
              local_108 = 2;
              local_af = 0;
              local_b0 = 0x32;
              local_cc = (undefined *)0x400110;
              local_ce = 0xdf;
            }
            else {
              uVar7 = FUN_80022264(0xffffff60,0xa0);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_e0 = (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0xffffffce,0xfa);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0xffffff60,0xa0);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e0 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              local_d4 = FLOAT_803e0280;
              local_108 = 200;
              local_af = 0x10;
              local_cc = &DAT_80000108;
              local_ce = 0x166;
            }
          }
          else {
            if (iVar8 < 700) goto LAB_800aee9c;
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
              param_3 = &DAT_8039cf68;
            }
            if (param_3 != (short *)0x0) {
              local_e0 = *(float *)(param_3 + 6) - *(float *)(puVar6 + 0xc);
              local_dc = *(float *)(param_3 + 8) - *(float *)(puVar6 + 0xe);
              local_d8 = *(float *)(param_3 + 10) - *(float *)(puVar6 + 0x10);
            }
            local_d4 = FLOAT_803e0228;
            local_108 = 0x14;
            local_b0 = 0xff;
            local_cc = (undefined *)0x80210;
            local_c8 = 0x100;
            local_ce = (short)uVar15 + -0x28c;
          }
        }
        else if (iVar8 == 0x322) {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          local_d4 = FLOAT_803e0184;
          local_108 = 0x50;
          local_cc = (undefined *)0x180200;
          local_c8 = 0x5000000;
          local_ce = 0xc90;
          local_b0 = 0xa5;
        }
        else if (iVar8 < 0x322) {
          if (iVar8 == 800) {
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
              param_3 = &DAT_8039cf68;
            }
            uVar7 = FUN_80022264(0xfffffffe,2);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e0288 * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(2,5);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e02f4 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(1,3);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803e0380 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
            local_d4 = FLOAT_803e01d0;
            local_108 = 0x28;
            local_c8 = 0x5000000;
            local_cc = (undefined *)0x180208;
            local_ce = 0xc8f;
          }
          else {
            if (iVar8 < 800) goto LAB_800aee9c;
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
              param_3 = &DAT_8039cf68;
            }
            uVar7 = FUN_80022264(0,4);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e8 = FLOAT_803e014c * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(2,4);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e4 = FLOAT_803e0384 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
            local_d4 = FLOAT_803e0168;
            local_108 = 100;
            local_cc = (undefined *)0x1180200;
            local_c8 = 0x5000000;
            local_ce = 0xc90;
          }
        }
        else if (iVar8 < 0x324) {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
          }
          uVar7 = FUN_80022264(0xffffffea,0x15);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e034c * (float)(local_78 - DOUBLE_803e0390) + local_e0;
          uStack_7c = FUN_80022264(0xffffffe9,0x16);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803e0350 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390) + local_dc;
          uStack_84 = FUN_80022264(0xffffffe9,0x19);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803e0354 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390) + local_d8;
          uVar7 = FUN_80022264(1,6);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0358 * (float)(local_90 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(7,0xf);
          local_108 = uVar7 + 5;
          local_ce = 0xc9a;
          local_cc = (undefined *)0x100210;
          local_c8 = 0x4000800;
          if (param_6 != (float *)0x0) {
            cVar5 = *(char *)param_6;
            if (cVar5 == '\x01') {
              local_c4 = 0x2898;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0x6574;
              local_b6 = 0x9f9;
              local_b4 = 0xffff;
              local_c8 = 0x4000820;
            }
            else if (cVar5 == '\x02') {
              local_c4 = 0xff65;
              local_c0 = 0xd23c;
              local_bc = 0x7fff;
              local_b8 = 0xffc4;
              local_b6 = 0xdc81;
              local_b4 = 0x2603;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803e035c;
              local_108 = uVar7 + 0xc;
            }
            else if (cVar5 == '\x03') {
              local_c4 = 0xfebe;
              local_c0 = 0x5cb2;
              local_bc = 0xfd01;
              local_b8 = 0xfd2c;
              local_b6 = 0x8e5;
              local_b4 = 0x1f5;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803e0360;
              local_108 = uVar7 + 0x19;
            }
            else if (cVar5 == '\x04') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0;
              local_b6 = 0xffff;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803e0360;
            }
            else if (cVar5 == '\x05') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0xffff;
              local_b6 = 0;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803e0360;
            }
            else if (cVar5 == '\x06') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0xffff;
              local_b6 = 0x7fff;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803e0360;
            }
            else if (cVar5 == '\a') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0xffff;
              local_b6 = 0xffff;
              local_b4 = 0;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803e0360;
            }
            else if (cVar5 == '\b') {
              local_c4 = 0xffff;
              local_c0 = 0xffff;
              local_bc = 0xffff;
              local_b8 = 0;
              local_b6 = 0xffff;
              local_b4 = 0xffff;
              local_c8 = 0x4000820;
              local_d4 = local_d4 * FLOAT_803e0360;
            }
          }
        }
      }
      else if (iVar8 == 0x3df) {
        uVar7 = FUN_80022264(0xffffff9c,100);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = FLOAT_803e014c * (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0xffffff9c,100);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = FLOAT_803e014c *
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uStack_84 = FUN_80022264(0xffffff9c,100);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = FLOAT_803e014c *
                   (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
        uVar7 = FUN_80022264(8,10);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e8 = FLOAT_803e0288 * (float)(local_90 - DOUBLE_803e0390);
        uVar7 = FUN_80022264(0,0x28);
        if (uVar7 == 0) {
          uVar7 = FUN_80022264(0x15,0x29);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0148 * (float)(local_78 - DOUBLE_803e0390);
          local_108 = 0x1cc;
        }
        else {
          uVar7 = FUN_80022264(8,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0148 * (float)(local_78 - DOUBLE_803e0390);
          local_108 = FUN_80022264(0x5a,0x78);
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
      else if (iVar8 < 0x3df) {
        if (iVar8 == 0x351) {
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          local_e4 = FLOAT_803e0388;
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          uVar7 = FUN_80022264(0x32,100);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0298 * (float)(local_78 - DOUBLE_803e0390);
          local_108 = FUN_80022264(0x28,0x50);
          local_cc = (undefined *)0x8100200;
          local_c8 = 0x5000000;
          local_ce = 0xc8f;
        }
        else if (iVar8 < 0x351) {
          if (iVar8 == 0x328) {
            uVar7 = FUN_80022264(0xffffff9c,100);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e01e8 * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xffffff9c,100);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e01e8 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0xffffff9c,100);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803e01e8 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_108 = FUN_80022264(4,0xd);
            local_cc = (undefined *)0x180210;
            local_c8 = 0x4000800;
            local_d4 = FLOAT_803e037c;
            local_ce = 0xc9d;
          }
          else if (iVar8 < 0x328) {
            if (0x326 < iVar8) goto LAB_800aee9c;
            FUN_80022264(1,1);
            local_ec = FLOAT_803e015c;
            FUN_80022264(1,1);
            local_e8 = FLOAT_803e015c;
            FUN_80022264(1,1);
            local_e4 = FLOAT_803e015c;
            FUN_80022264(1,1);
            local_e0 = FLOAT_803e015c;
            FUN_80022264(1,1);
            local_dc = FLOAT_803e015c;
            FUN_80022264(1,1);
            local_d8 = FLOAT_803e015c;
            uVar7 = FUN_80022264(10,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e0370 * (float)(local_78 - DOUBLE_803e0390);
            local_108 = FUN_80022264(1,1);
            local_108 = local_108 + 0x17;
            local_ce = 0xc99;
            local_cc = (undefined *)0x180210;
            local_b0 = 0x7d;
            if (param_6 != (float *)0x0) {
              cVar5 = *(char *)param_6;
              if (cVar5 == '\x01') {
                local_c4 = 0x2898;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0x6574;
                local_b6 = 0x9f9;
                local_b4 = 0xffff;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803e0374;
              }
              else if (cVar5 == '\x02') {
                local_c4 = 0xff65;
                local_c0 = 0xd23c;
                local_bc = 0x7fff;
                local_b8 = 0xffc4;
                local_b6 = 0xdc81;
                local_b4 = 0x2603;
                local_c8 = local_c8 | 0x20;
              }
              else if (cVar5 == '\x03') {
                local_c4 = 0xfebe;
                local_c0 = 0x5cb2;
                local_bc = 0xfd01;
                local_b8 = 0xfd2c;
                local_b6 = 0x8e5;
                local_b4 = 0x1f5;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803e0378;
              }
              else if (cVar5 == '\x04') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0;
                local_b6 = 0xffff;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803e0360;
              }
              else if (cVar5 == '\x05') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0xffff;
                local_b6 = 0;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803e0360;
              }
              else if (cVar5 == '\x06') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0xffff;
                local_b6 = 0x7fff;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803e0360;
              }
              else if (cVar5 == '\a') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0xffff;
                local_b6 = 0xffff;
                local_b4 = 0;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803e0360;
              }
              else if (cVar5 == '\b') {
                local_c4 = 0xffff;
                local_c0 = 0xffff;
                local_bc = 0xffff;
                local_b8 = 0;
                local_b6 = 0xffff;
                local_b4 = 0xffff;
                local_c8 = local_c8 | 0x20;
                local_d4 = local_d4 * FLOAT_803e0360;
              }
            }
          }
          else {
            if (0x329 < iVar8) goto LAB_800aee9c;
            uVar7 = FUN_80022264(0xffffff9c,100);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803e014c * (float)(local_78 - DOUBLE_803e0390);
            local_dc = FLOAT_803e0238;
            uStack_7c = FUN_80022264(0xffffff9c,100);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_d8 = FLOAT_803e014c *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(100,200);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_ec = FLOAT_803e0148 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(100,200);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e8 = FLOAT_803e0148 * (float)(local_90 - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0xffffff9c,100);
            local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e4 = FLOAT_803e0148 * (float)(local_98 - DOUBLE_803e0390);
            local_cc = (undefined *)0x1081010;
            uVar7 = FUN_80022264(0,3);
            if (uVar7 == 0) {
              uVar7 = FUN_80022264(0x28,0x50);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e023c * (float)(local_78 - DOUBLE_803e0390);
              local_b0 = 0x8c;
            }
            else {
              uVar7 = FUN_80022264(0x28,0x50);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e0240 * (float)(local_78 - DOUBLE_803e0390);
              local_b0 = 10;
              local_cc = (undefined *)((uint)local_cc | 0x100000);
            }
            uVar7 = FUN_80022264(0,10);
            if (uVar7 == 0) {
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
        else if (iVar8 == 0x3b9) {
          uVar7 = FUN_80022264(0xffffffec,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803e0168 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xffffffec,0x14);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_e4 = FLOAT_803e0168 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xffffffce,0x32);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e0 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0xffffffce,0x32);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = (float)(local_90 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0x1e,100);
          local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_dc = (float)(local_98 - DOUBLE_803e0390);
          local_d4 = FLOAT_803e014c;
          local_108 = 0x4b0;
          local_b0 = 200;
          local_cc = (undefined *)0x180100;
          local_ce = 0x62;
        }
        else if (iVar8 < 0x3b9) {
          if (iVar8 < 0x3b8) goto LAB_800aee9c;
          uVar7 = FUN_80022264(0,0x78);
          local_78 = (double)CONCAT44(0x43300000,0x3c - uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e0244 * (float)(local_78 - DOUBLE_803e0390);
          local_dc = FLOAT_803e0200;
          uVar7 = FUN_80022264(0,0x78);
          uStack_7c = 0x3c - uVar7 ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803e0244 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,0x50);
          uStack_84 = 0x28 - uVar7 ^ 0x80000000;
          local_88 = 0x43300000;
          local_ec = FLOAT_803e0160 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0,0x50);
          local_90 = (double)CONCAT44(0x43300000,0x28 - uVar7 ^ 0x80000000);
          local_e4 = FLOAT_803e0160 * (float)(local_90 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0x28,0x50);
          local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e8 = FLOAT_803e0160 * (float)(local_98 - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0x28,0x50);
          local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0220 * (float)(local_a0 - DOUBLE_803e0390);
          local_108 = 0xb4;
          local_af = 0;
          local_cc = (undefined *)0x80400201;
          local_ce = 0x47;
        }
        else {
          if (iVar8 < 0x3de) goto LAB_800aee9c;
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          if (param_3 == (short *)0x0) {
            uVar7 = FUN_80022264(0xfffffff6,10);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_e0 = FLOAT_803e014c * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xfffffff6,10);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_dc = FLOAT_803e014c *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0xfffffff6,10);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_d8 = FLOAT_803e014c *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          }
          else {
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
          }
          local_ec = FLOAT_803e015c;
          local_e8 = FLOAT_803e0188;
          local_e4 = FLOAT_803e015c;
          local_d4 = FLOAT_803e0184;
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
      else if (iVar8 == 0x51d) {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
          param_3 = &DAT_8039cf68;
        }
        local_104 = 700;
        local_ce = 0xc09;
        local_e0 = *(float *)(param_3 + 6);
        local_dc = *(float *)(param_3 + 8);
        uVar7 = FUN_80022264(10,0x14);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803e01a4 * (float)(local_78 - DOUBLE_803e0390);
        local_108 = 0xaa;
        local_cc = (undefined *)0xa0104;
        local_f8 = FLOAT_803e015c;
        local_f4 = FLOAT_803e015c;
        local_f0 = FLOAT_803e015c;
        local_102 = 0;
        local_100 = 0;
        local_fc = FLOAT_803e0150;
      }
      else if (iVar8 < 0x51d) {
        if (iVar8 == 999) {
          local_108 = 300;
          local_cc = (undefined *)0x80400500;
          uVar7 = FUN_80022264(0xfffffffc,4);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_ec = FLOAT_803e0170 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffffc,4);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_e4 = FLOAT_803e01d0 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0x28,0x50);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803e01e8 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e027c * (float)(local_90 - DOUBLE_803e0390);
          if (local_100 == 1) {
            local_ce = 0x160;
          }
          else if (local_100 < 1) {
            if (local_100 < 0) {
LAB_800a9b98:
              local_ce = 0xdf;
            }
            else {
              local_ce = 0xdd;
            }
          }
          else {
            if (2 < local_100) goto LAB_800a9b98;
            local_ce = 0xdf;
          }
          local_100 = 0;
        }
        else if (iVar8 < 999) {
          if (iVar8 < 0x3e6) goto LAB_800aee9c;
          uVar7 = FUN_80022264(0xfffffffc,4);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffffc,4);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(4,10);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803e02f4 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(0x28,0x50);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0220 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = 0x15e;
          local_10c = 0x85;
          local_b0 = 0xff;
          local_cc = (undefined *)0x80400201;
          local_ce = 0xdf;
        }
        else if (iVar8 == 0x51b) {
          uVar7 = FUN_80022264(0,0xf);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01e8 * (float)(local_78 - DOUBLE_803e0390) + FLOAT_803e01d0;
          uStack_7c = FUN_80022264(0xffffffce,0x32);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_e0 = FLOAT_803e014c *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xffffffce,0x32);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_dc = FLOAT_803e014c *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390) +
                     FLOAT_803e0200;
          uVar7 = FUN_80022264(0xffffffce,0x32);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d8 = FLOAT_803e014c * (float)(local_90 - DOUBLE_803e0390);
          local_ec = local_e0 / FLOAT_803e0224;
          local_e8 = local_dc / FLOAT_803e0224;
          local_e4 = local_d8 / FLOAT_803e0224;
          local_108 = FUN_80022264(0,0x14);
          local_108 = local_108 + 0x14;
          local_b0 = 0xff;
          local_cc = (undefined *)0x100110;
          local_ce = 0xe4;
        }
        else {
          if (iVar8 < 0x51b) goto LAB_800aee9c;
          uVar7 = FUN_80022264(0xffffffe2,0x1e);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e014c * (float)(local_78 - DOUBLE_803e0390);
          local_dc = FLOAT_803e021c;
          uStack_7c = FUN_80022264(0xffffffe2,0x1e);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = FLOAT_803e014c *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0x19,0x23);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_e8 = FLOAT_803e0160 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(100,0x96);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e0220 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = FUN_80022264(0x5a,0x78);
          local_cc = (undefined *)0x80100100;
          local_ce = 0x60;
          local_b8 = 0x7fff;
          local_b6 = 0x7fff;
          local_b4 = 0x7fff;
          local_c4 = FUN_80022264(0,10);
          local_c4 = local_c4 * 0xacf;
          local_c8 = 0x20;
          local_c0 = local_c4;
          local_bc = local_c4;
        }
      }
      else if (iVar8 == 0x52a) {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
          param_3 = &DAT_8039cf68;
        }
        if (param_3 == (short *)0x0) goto LAB_800aee9c;
        local_e0 = *(float *)(param_3 + 6);
        local_dc = *(float *)(param_3 + 8);
        local_d8 = *(float *)(param_3 + 10);
        local_d4 = FLOAT_803e020c;
        local_108 = 10;
        local_b0 = 0xff;
        local_af = 0x10;
        local_cc = (undefined *)0x80440202;
        local_ce = 0x4f9;
        local_c8 = 0x2000000;
      }
      else if (iVar8 < 0x52a) {
        if (iVar8 == 0x51f) {
          local_dc = FLOAT_803e0210;
          local_d4 = FLOAT_803e0214;
          local_108 = 0x1e;
          local_b0 = 0xff;
          local_af = 0x10;
          local_cc = (undefined *)0x88140200;
          local_ce = 0x159;
        }
        else {
          if (0x51e < iVar8) goto LAB_800aee9c;
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          if (param_3 == (short *)0x0) goto LAB_800aee9c;
          local_e0 = *(float *)(param_3 + 6);
          local_dc = *(float *)(param_3 + 8);
          local_d8 = *(float *)(param_3 + 10);
          local_d4 = FLOAT_803e0218;
          local_108 = 10;
          local_b0 = 0xff;
          local_af = 0x10;
          local_cc = (undefined *)0x80440202;
          local_ce = 0x156;
        }
      }
      else {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
          param_3 = &DAT_8039cf68;
        }
        if (param_3 != (short *)0x0) {
          local_e0 = *(float *)(param_3 + 6) - *(float *)(puVar6 + 0xc);
          local_dc = *(float *)(param_3 + 8) - *(float *)(puVar6 + 0xe);
          local_d8 = *(float *)(param_3 + 10) - *(float *)(puVar6 + 0x10);
        }
        uVar7 = FUN_80022264(0,0x28);
        if (uVar7 == 0) {
          local_d4 = FLOAT_803e0154;
        }
        else {
          local_d4 = FLOAT_803e0194;
        }
        local_108 = 0x14;
        local_b0 = 0xff;
        local_cc = (undefined *)0x80210;
        local_ce = (short)uVar15 + -0x3d5;
      }
    }
    else if (iVar8 == 0x552) {
      if (param_3 == (short *)0x0) {
        DAT_8039cf74 = FLOAT_803e015c;
        DAT_8039cf78 = FLOAT_803e015c;
        DAT_8039cf7c = FLOAT_803e015c;
        DAT_8039cf70 = FLOAT_803e0150;
        DAT_8039cf68 = 0;
        DAT_8039cf6a = 0;
        DAT_8039cf6c = 0;
        DAT_8039cf6e = 0;
      }
      local_d8 = FLOAT_803e0198;
      local_d4 = FLOAT_803e016c;
      local_108 = 0x23;
      local_b0 = 0x9b;
      local_cc = (undefined *)0xa100210;
      local_ce = 0x91;
    }
    else if (iVar8 < 0x552) {
      if (iVar8 == 0x546) {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
          param_3 = &DAT_8039cf68;
        }
        local_d4 = FLOAT_803e01b4 * *(float *)(param_3 + 4);
        local_108 = 4;
        local_cc = (undefined *)0x480000;
        local_c8 = 0x2000002;
        local_ce = 0xc0e;
        local_b0 = 0x73;
      }
      else if (iVar8 < 0x546) {
        if (iVar8 == 0x53c) {
          if (param_6 != (float *)0x0) {
            iVar1 = (int)(FLOAT_803e01c8 * (FLOAT_803e0150 - *param_6));
            local_78 = (double)(longlong)iVar1;
            local_b0 = (undefined)iVar1;
            FUN_80137cd0();
          }
          local_d4 = FLOAT_803e01cc;
          local_cc = (undefined *)0x80000;
          local_c8 = 0x2000002;
          local_108 = 0;
          local_ce = 0xe4;
        }
        else if (iVar8 < 0x53c) {
          if (iVar8 == 0x534) {
            local_dc = FLOAT_803e0200;
            uVar7 = FUN_80022264(0xfffffff1,0xf);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e0170 * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xfffffff1,0xf);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e0170 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            local_e4 = FLOAT_803e0204;
            local_11c = FLOAT_803e015c;
            local_118 = FLOAT_803e015c;
            local_114 = FLOAT_803e015c;
            local_120 = FLOAT_803e0150;
            local_124 = puVar6[2];
            local_126 = puVar6[1];
            local_128 = *puVar6;
            FUN_80021b8c(&local_128,&local_ec);
            local_b0 = 0xff;
            uStack_84 = FUN_80022264(10,0x14);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_d4 = FLOAT_803e0208 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_cc = (undefined *)0x2000110;
            local_c8 = 0x200000;
            local_108 = 0x19;
            local_ce = 0x156;
          }
          else if (iVar8 < 0x534) {
            if (iVar8 == 0x532) {
              if (param_3 == (short *)0x0) {
                DAT_8039cf74 = FLOAT_803e015c;
                DAT_8039cf78 = FLOAT_803e015c;
                DAT_8039cf7c = FLOAT_803e015c;
                DAT_8039cf70 = FLOAT_803e0150;
                DAT_8039cf68 = 0;
                DAT_8039cf6a = 0;
                DAT_8039cf6c = 0;
                DAT_8039cf6e = 0;
                param_3 = &DAT_8039cf68;
              }
              if (param_3 == (short *)0x0) goto LAB_800aee9c;
              local_e0 = *(float *)(param_3 + 6);
              local_dc = *(float *)(param_3 + 8);
              local_d8 = *(float *)(param_3 + 10);
              uVar7 = FUN_80022264(0xffffffe2,0x1e);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803e01e8 * (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(0xffffffe2,0x1e);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_e8 = FLOAT_803e01e8 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(0x14,0x1e);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e4 = FLOAT_803e01ec *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              local_11c = FLOAT_803e015c;
              local_118 = FLOAT_803e015c;
              local_114 = FLOAT_803e015c;
              local_120 = FLOAT_803e0150;
              local_124 = puVar6[2];
              local_126 = puVar6[1];
              local_128 = *puVar6;
              FUN_80021b8c(&local_128,&local_ec);
              local_b0 = 0xcd;
              local_cc = (undefined *)0x100110;
              uVar7 = FUN_80022264(0x96,200);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e01f0 * (float)(local_90 - DOUBLE_803e0390);
              local_108 = 0x28;
              local_ce = 0x89;
            }
            else if (iVar8 < 0x532) {
              if (param_3 == (short *)0x0) {
                DAT_8039cf74 = FLOAT_803e015c;
                DAT_8039cf78 = FLOAT_803e015c;
                DAT_8039cf7c = FLOAT_803e015c;
                DAT_8039cf70 = FLOAT_803e0150;
                DAT_8039cf68 = 0;
                DAT_8039cf6a = 0;
                DAT_8039cf6c = 0;
                DAT_8039cf6e = 0;
                param_3 = &DAT_8039cf68;
              }
              if (param_3 != (short *)0x0) {
                local_e0 = *(float *)(param_3 + 6) - *(float *)(puVar6 + 0xc);
                local_dc = *(float *)(param_3 + 8) - *(float *)(puVar6 + 0xe);
                local_d8 = *(float *)(param_3 + 10) - *(float *)(puVar6 + 0x10);
                local_e4 = FLOAT_803e0158;
              }
              local_d4 = FLOAT_803e0194;
              local_108 = 100;
            }
            else {
              if (param_3 == (short *)0x0) {
                DAT_8039cf74 = FLOAT_803e015c;
                DAT_8039cf78 = FLOAT_803e015c;
                DAT_8039cf7c = FLOAT_803e015c;
                DAT_8039cf70 = FLOAT_803e0150;
                DAT_8039cf68 = 0;
                DAT_8039cf6a = 0;
                DAT_8039cf6c = 0;
                DAT_8039cf6e = 0;
                param_3 = &DAT_8039cf68;
              }
              if (param_3 == (short *)0x0) goto LAB_800aee9c;
              local_e0 = *(float *)(param_3 + 6);
              local_dc = *(float *)(param_3 + 8);
              local_d8 = *(float *)(param_3 + 10);
              uVar7 = FUN_80022264(0xffffffe2,0x1e);
              local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_ec = FLOAT_803e01e8 * (float)(local_78 - DOUBLE_803e0390);
              uStack_7c = FUN_80022264(8,10);
              uStack_7c = uStack_7c ^ 0x80000000;
              local_80 = 0x43300000;
              local_e8 = FLOAT_803e0168 *
                         (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
              uStack_84 = FUN_80022264(10,0x1e);
              uStack_84 = uStack_84 ^ 0x80000000;
              local_88 = 0x43300000;
              local_e4 = FLOAT_803e01f4 *
                         (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
              local_11c = FLOAT_803e015c;
              local_118 = FLOAT_803e015c;
              local_114 = FLOAT_803e015c;
              local_120 = FLOAT_803e0150;
              local_124 = puVar6[2];
              local_126 = puVar6[1];
              local_128 = *puVar6;
              FUN_80021b8c(&local_128,&local_ec);
              uVar7 = FUN_80022264(8,0x14);
              local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              local_d4 = FLOAT_803e0154 * (float)(local_90 - DOUBLE_803e0390);
              local_108 = FUN_80022264(0x3c,0x78);
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
            if (0x535 < iVar8) goto LAB_800aee9c;
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
              param_3 = &DAT_8039cf68;
            }
            if (param_3 == (short *)0x0) goto LAB_800aee9c;
            local_e0 = *(float *)(param_3 + 6);
            local_dc = *(float *)(param_3 + 8);
            local_d8 = *(float *)(param_3 + 10);
            uVar7 = FUN_80022264(0xffffffe2,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e0168 * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xffffffe2,0x1e);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e0168 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0x14,0x1e);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803e01f8 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_11c = FLOAT_803e015c;
            local_118 = FLOAT_803e015c;
            local_114 = FLOAT_803e015c;
            local_120 = FLOAT_803e0150;
            local_124 = puVar6[2];
            local_126 = puVar6[1];
            local_128 = *puVar6;
            FUN_80021b8c(&local_128,&local_ec);
            local_b0 = 0xff;
            uVar7 = FUN_80022264(0x96,200);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01fc * (float)(local_90 - DOUBLE_803e0390);
            local_cc = (undefined *)0x2000110;
            local_c8 = 0x2200000;
            local_108 = 0x19;
            local_ce = 0x24;
          }
        }
        else if (iVar8 == 0x53f) {
          local_b0 = 0x37;
          local_d4 = FLOAT_803e014c;
          local_cc = (undefined *)0x80010;
          local_c8 = 2;
          local_108 = 1;
          local_ce = 0x156;
        }
        else if (iVar8 < 0x53f) {
          if (iVar8 < 0x53e) {
            local_b0 = 0x69;
            local_d4 = FLOAT_803e01d0;
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
            (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
            local_d8 = FLOAT_803e01d4;
            local_b0 = 0x69;
            local_d4 = FLOAT_803e01d8;
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
            (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
            local_d8 = FLOAT_803e01dc;
            local_b0 = 0x69;
            local_d4 = FLOAT_803e01e0;
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
            local_e0 = FLOAT_803e01e4;
            local_d4 = FLOAT_803e0188;
            local_cc = (undefined *)0x80010;
            local_c8 = 2;
            local_108 = 1;
            local_ce = 100;
          }
        }
        else {
          if (iVar8 < 0x545) goto LAB_800aee9c;
          if (param_3 == (short *)0x0) {
            DAT_8039cf74 = FLOAT_803e015c;
            DAT_8039cf78 = FLOAT_803e015c;
            DAT_8039cf7c = FLOAT_803e015c;
            DAT_8039cf70 = FLOAT_803e0150;
            DAT_8039cf68 = 0;
            DAT_8039cf6a = 0;
            DAT_8039cf6c = 0;
            DAT_8039cf6e = 0;
            param_3 = &DAT_8039cf68;
          }
          local_d4 = FLOAT_803e01b0 * *(float *)(param_3 + 4);
          local_108 = 4;
          local_cc = (undefined *)0x480000;
          local_c8 = 2;
          local_ce = 0x527;
          local_b0 = 0x69;
        }
      }
      else if (iVar8 == 0x54c) {
        uVar7 = FUN_80022264(0xfffffff6,10);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = FLOAT_803e0188 * (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0xfffffff6,10);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = FLOAT_803e0188 *
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uStack_84 = FUN_80022264(0xfffffff6,10);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = FLOAT_803e0188 *
                   (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
        uVar7 = FUN_80022264(10,0x14);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803e01a4 * (float)(local_90 - DOUBLE_803e0390);
        local_108 = FUN_80022264(100,0x96);
        local_b0 = 0xff;
        local_cc = (undefined *)0x80480110;
        if (param_6 != (float *)0x0) {
          local_cc = (undefined *)0xc0480110;
        }
        local_ce = 0x157;
      }
      else if (iVar8 < 0x54c) {
        if (iVar8 == 0x549) {
          uVar7 = FUN_80022264(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e0188 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffff6,10);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803e0188 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xfffffff6,10);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803e0188 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(10,0x14);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a4 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = FUN_80022264(100,0x96);
          local_b0 = 0xff;
          local_cc = (undefined *)0x80480110;
          if (param_6 != (float *)0x0) {
            local_cc = (undefined *)0xc0480110;
          }
          local_ce = 0x85;
        }
        else if (iVar8 < 0x549) {
          if (iVar8 < 0x548) {
            local_e0 = FLOAT_803e01b8;
            uVar7 = FUN_80022264(0xffffffb0,0x50);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_dc = (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0xffffff9c,100);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e0168 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
            }
            local_d4 = FLOAT_803e01bc;
            local_108 = 300;
            local_cc = (undefined *)0x480000;
            local_c8 = 0x2000000;
            local_ce = 0xc0e;
            local_b0 = 0xff;
            local_10c = 0x548;
            local_102 = 0;
            local_104 = 0;
            local_f8 = FLOAT_803e01c0;
            local_f4 = FLOAT_803e015c;
            local_f0 = FLOAT_803e015c;
            local_fc = FLOAT_803e0150;
            local_108 = FUN_80022264(0,0x14);
            local_108 = local_108 + 0x28;
            local_af = 0x10;
            local_cc = (undefined *)((uint)local_cc | 0x20000);
          }
          else {
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
            }
            local_d4 = FLOAT_803e01c4;
            local_108 = 0x50;
            local_cc = (undefined *)0x80201;
            local_c8 = 0x2000000;
            local_ce = 0xc0e;
            local_b0 = 0xff;
          }
        }
        else if (iVar8 < 0x54b) {
          uVar7 = FUN_80022264(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e0188 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffff6,10);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803e0188 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xfffffff6,10);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803e0188 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(10,0x14);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a4 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = FUN_80022264(100,0x96);
          local_b0 = 0xff;
          local_cc = (undefined *)0x80480110;
          if (param_6 != (float *)0x0) {
            local_cc = (undefined *)0xc0480110;
          }
          local_ce = 0x84;
        }
        else {
          uVar7 = FUN_80022264(0xfffffff6,10);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = FLOAT_803e0188 * (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffff6,10);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_dc = FLOAT_803e0188 *
                     (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
          uStack_84 = FUN_80022264(0xfffffff6,10);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_d8 = FLOAT_803e0188 *
                     (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
          uVar7 = FUN_80022264(10,0x14);
          local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a4 * (float)(local_90 - DOUBLE_803e0390);
          local_108 = FUN_80022264(100,0x96);
          local_b0 = 0xff;
          local_cc = (undefined *)0x80480110;
          if (param_6 != (float *)0x0) {
            local_cc = (undefined *)0xc0480110;
          }
          local_ce = 0xc0f;
        }
      }
      else if (iVar8 == 0x54f) {
        if (param_6 != (float *)0x0) {
          cVar5 = *(char *)param_6;
        }
        if (cVar5 == '\x01') {
          uVar7 = FUN_80022264(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a4 * (float)(local_78 - DOUBLE_803e0390);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x202;
        }
        else if (cVar5 == '\x02') {
          uVar7 = FUN_80022264(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a8 * (float)(local_78 - DOUBLE_803e0390);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x102;
        }
        else {
          uVar7 = FUN_80022264(0x12,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01ac * (float)(local_78 - DOUBLE_803e0390);
          local_cc = (undefined *)0xc0800;
          local_c8 = 2;
        }
        local_108 = 1;
        local_b0 = 0x60;
        local_ce = 0xc0f;
      }
      else if (iVar8 < 0x54f) {
        if (iVar8 < 0x54e) {
          if (param_6 == (float *)0x0) {
            cVar5 = '\0';
          }
          else {
            cVar5 = *(char *)param_6;
          }
          if (cVar5 == '\x01') {
            uVar7 = FUN_80022264(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01a4 * (float)(local_78 - DOUBLE_803e0390);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x202;
          }
          else if (cVar5 == '\x02') {
            uVar7 = FUN_80022264(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01a8 * (float)(local_78 - DOUBLE_803e0390);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x102;
          }
          else {
            uVar7 = FUN_80022264(0x12,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01ac * (float)(local_78 - DOUBLE_803e0390);
            local_cc = (undefined *)0xc0800;
            local_c8 = 2;
          }
          local_108 = 1;
          local_b0 = 0x60;
          local_ce = 0x85;
        }
        else {
          if (param_6 != (float *)0x0) {
            cVar5 = *(char *)param_6;
          }
          if (cVar5 == '\x01') {
            uVar7 = FUN_80022264(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01a4 * (float)(local_78 - DOUBLE_803e0390);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x202;
          }
          else if (cVar5 == '\x02') {
            uVar7 = FUN_80022264(10,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01a8 * (float)(local_78 - DOUBLE_803e0390);
            local_cc = (undefined *)0x4c0800;
            local_c8 = 0x102;
          }
          else {
            uVar7 = FUN_80022264(0x12,0x14);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01ac * (float)(local_78 - DOUBLE_803e0390);
            local_cc = (undefined *)0xc0800;
            local_c8 = 2;
          }
          local_108 = 1;
          local_b0 = 0x60;
          local_ce = 0x84;
        }
      }
      else if (iVar8 < 0x551) {
        if (param_6 != (float *)0x0) {
          cVar5 = *(char *)param_6;
        }
        if (cVar5 == '\x01') {
          uVar7 = FUN_80022264(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a4 * (float)(local_78 - DOUBLE_803e0390);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x202;
        }
        else if (cVar5 == '\x02') {
          uVar7 = FUN_80022264(10,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01a8 * (float)(local_78 - DOUBLE_803e0390);
          local_cc = (undefined *)0x4c0800;
          local_c8 = 0x102;
        }
        else {
          uVar7 = FUN_80022264(0x12,0x14);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_d4 = FLOAT_803e01ac * (float)(local_78 - DOUBLE_803e0390);
          local_cc = (undefined *)0xc0800;
          local_c8 = 2;
        }
        local_108 = 1;
        local_b0 = 0x60;
        local_ce = 0x157;
      }
      else {
        if (param_3 == (short *)0x0) {
          DAT_8039cf74 = FLOAT_803e015c;
          DAT_8039cf78 = FLOAT_803e015c;
          DAT_8039cf7c = FLOAT_803e015c;
          DAT_8039cf70 = FLOAT_803e0150;
          DAT_8039cf68 = 0;
          DAT_8039cf6a = 0;
          DAT_8039cf6c = 0;
          DAT_8039cf6e = 0;
        }
        local_d8 = FLOAT_803e0198;
        local_d4 = FLOAT_803e016c;
        local_108 = 0x23;
        local_b0 = 0x9b;
        local_cc = (undefined *)0x100210;
        local_ce = 0x91;
      }
    }
    else if (iVar8 == 0x55e) {
      if (param_3 == (short *)0x0) {
        DAT_8039cf74 = FLOAT_803e015c;
        DAT_8039cf78 = FLOAT_803e015c;
        DAT_8039cf7c = FLOAT_803e015c;
        DAT_8039cf70 = FLOAT_803e0150;
        DAT_8039cf68 = 0;
        DAT_8039cf6a = 0;
        DAT_8039cf6c = 0;
        DAT_8039cf6e = 0;
        param_3 = &DAT_8039cf68;
      }
      uVar7 = FUN_80022264(0xfffffffa,6);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_dc = *(float *)(param_3 + 8) + (float)(local_78 - DOUBLE_803e0390);
      uStack_7c = FUN_80022264(0xffffff9c,100);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      local_ec = FLOAT_803e0168 * (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
      uStack_84 = FUN_80022264(0xffffff9c,100);
      uStack_84 = uStack_84 ^ 0x80000000;
      local_88 = 0x43300000;
      local_e4 = FLOAT_803e0168 * (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
      local_d4 = FLOAT_803e0194;
      local_108 = 0x12;
      local_b0 = 0xff;
      local_cc = (undefined *)0x400010;
      local_c8 = 0x400008;
      local_ce = 0xe4;
    }
    else if (iVar8 < 0x55e) {
      if (iVar8 == 0x558) {
LAB_800a6d78:
        local_dc = FLOAT_803e017c;
        if (param_6 == (float *)0x0) {
          local_e8 = FLOAT_803e0188;
        }
        else {
          local_e8 = FLOAT_803e018c;
        }
        local_d4 = FLOAT_803e0190;
        local_108 = 0xaf;
        local_b0 = 0xff;
        local_cc = (undefined *)0x500010;
        local_c8 = 0x400200;
        local_ce = 0xe4;
        (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
LAB_800a6df8:
        local_dc = FLOAT_803e017c;
        if (param_6 == (float *)0x0) {
          local_e8 = FLOAT_803e018c;
        }
        else {
          local_e8 = FLOAT_803e0188;
        }
        local_d4 = FLOAT_803e0160;
        local_108 = 0xaf;
        local_b0 = 0xff;
        local_cc = (undefined *)0x500010;
        local_c8 = 0x400100;
        local_ce = 0xe4;
        (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
      }
      else {
        if (iVar8 < 0x558) {
          if (iVar8 == 0x555) goto LAB_800aee9c;
          if (0x554 < iVar8) {
            if (iVar8 < 0x557) {
              local_dc = FLOAT_803e017c;
              local_d4 = FLOAT_803e0180;
              local_108 = 0xaf;
              local_b0 = 0xff;
              local_cc = (undefined *)0x500010;
              local_c8 = 0x400200;
              local_ce = 0xe4;
              (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
              goto LAB_800a6c34;
            }
            goto LAB_800a6cf8;
          }
          if (iVar8 < 0x554) {
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
            }
            uVar7 = FUN_80022264(0xffffffe2,0x1e);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e0170 * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(0x14,0x1e);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e016c *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0xffffffe2,0x1e);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803e0170 *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            local_d8 = FLOAT_803e0198;
            local_11c = FLOAT_803e015c;
            local_118 = FLOAT_803e015c;
            local_114 = FLOAT_803e015c;
            local_120 = FLOAT_803e0150;
            local_124 = 0;
            local_126 = 0;
            local_128 = *puVar6;
            FUN_80021b8c(&local_128,&local_e0);
            local_d4 = FLOAT_803e01a0;
            local_108 = 0x91;
            local_b0 = 0xff;
            local_cc = (undefined *)0x3000010;
            local_c8 = 0x2600000;
            local_ce = 0xe4;
          }
          else {
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
            }
            local_d8 = FLOAT_803e0198;
            local_d4 = FLOAT_803e019c;
            local_108 = 0x37;
            local_b0 = 0x9b;
            local_cc = (undefined *)0xa100210;
            local_ce = 0x73;
          }
          goto LAB_800aedbc;
        }
        if (iVar8 != 0x55b) {
          if (0x55a < iVar8) {
            if (iVar8 < 0x55d) {
LAB_800a6c34:
              local_dc = FLOAT_803e017c;
              local_d4 = FLOAT_803e0168;
              local_108 = 0xaf;
              local_b0 = 0xff;
              local_cc = (undefined *)0x500010;
              local_c8 = 0x400100;
              local_ce = 0xe4;
              (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
            }
            local_dc = FLOAT_803e017c;
            local_d4 = FLOAT_803e0184;
            local_108 = 0x2d;
            local_b0 = 0xff;
            local_cc = (undefined *)0x100210;
            local_c8 = 0x200;
            local_ce = 0xe4;
            (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
LAB_800a6cf8:
            local_dc = FLOAT_803e017c;
            if (param_6 == (float *)0x0) {
              local_e8 = FLOAT_803e018c;
            }
            else {
              local_e8 = FLOAT_803e0188;
            }
            local_d4 = FLOAT_803e0190;
            local_108 = 0xaf;
            local_b0 = 0xff;
            local_cc = (undefined *)0x500010;
            local_c8 = 0x400200;
            local_ce = 0xe4;
            (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0,iVar8,0);
            goto LAB_800a6d78;
          }
          if (0x559 < iVar8) {
            if (param_3 == (short *)0x0) {
              DAT_8039cf74 = FLOAT_803e015c;
              DAT_8039cf78 = FLOAT_803e015c;
              DAT_8039cf7c = FLOAT_803e015c;
              DAT_8039cf70 = FLOAT_803e0150;
              DAT_8039cf68 = 0;
              DAT_8039cf6a = 0;
              DAT_8039cf6c = 0;
              DAT_8039cf6e = 0;
            }
            uVar7 = FUN_80022264(0xffffffd8,0x28);
            local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_ec = FLOAT_803e024c * (float)(local_78 - DOUBLE_803e0390);
            uStack_7c = FUN_80022264(10,0x50);
            uStack_7c = uStack_7c ^ 0x80000000;
            local_80 = 0x43300000;
            local_e8 = FLOAT_803e01e8 *
                       (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
            uStack_84 = FUN_80022264(0xffffffd8,0x28);
            uStack_84 = uStack_84 ^ 0x80000000;
            local_88 = 0x43300000;
            local_e4 = FLOAT_803e024c *
                       (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
            uVar7 = FUN_80022264(5,0x19);
            local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_d4 = FLOAT_803e01a8 * (float)(local_90 - DOUBLE_803e0390);
            local_108 = FUN_80022264(0x122,0x15e);
            local_b0 = 0xff;
            uVar7 = FUN_80022264(0,0xffff);
            local_104 = (short)uVar7;
            uVar7 = FUN_80022264(0,0xffff);
            local_102 = (short)uVar7;
            uVar7 = FUN_80022264(0,0xffff);
            local_104 = (short)uVar7;
            uVar7 = FUN_80022264(0xe6,800);
            local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_f8 = (float)(local_98 - DOUBLE_803e0390);
            uVar7 = FUN_80022264(0xe6,800);
            local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
            local_f4 = (float)(local_a0 - DOUBLE_803e0390);
            uStack_a4 = FUN_80022264(0xe6,800);
            uStack_a4 = uStack_a4 ^ 0x80000000;
            local_a8 = 0x43300000;
            local_f0 = (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e0390);
            local_c8 = 0x1000020;
            local_cc = (undefined *)0x86000008;
            local_c4 = FUN_80022264(0,0xfff);
            local_c4 = local_c4 + 0xf000;
            local_b8 = (ushort)local_c4;
            local_c0 = 0xe000;
            local_b6 = 0xe000;
            local_bc = 0xe000;
            local_b4 = 0xe000;
            local_ce = 0x567;
            goto LAB_800aedbc;
          }
          goto LAB_800a6df8;
        }
      }
      local_dc = FLOAT_803e017c;
      if (param_6 == (float *)0x0) {
        local_e8 = FLOAT_803e0188;
      }
      else {
        local_e8 = FLOAT_803e018c;
      }
      local_d4 = FLOAT_803e0160;
      local_108 = 0xaf;
      local_b0 = 0xff;
      local_cc = (undefined *)0x500010;
      local_c8 = 0x400100;
      local_ce = 0xe4;
    }
    else if (iVar8 == 0x68c) {
      local_d4 = FLOAT_803e0168;
      local_108 = 0x5f;
      local_cc = (undefined *)0x1180200;
      local_ce = 0x62;
      local_b8 = 0;
      local_b6 = 0;
      uVar7 = FUN_80022264(0x8000,0xffff);
      local_b4 = (ushort)uVar7;
      local_c4 = 0;
      local_c0 = FUN_80022264(0,0x8000);
      local_bc = FUN_80022264(0,0xffff);
      local_c8 = 0x20;
    }
    else if (iVar8 < 0x68c) {
      if (iVar8 == 0x565) {
        local_d4 = FLOAT_803e0150;
        local_108 = 0x14;
        local_af = 0;
        local_cc = (undefined *)0x210;
        local_c8 = 0x800;
        local_ce = 0x5b1;
      }
      else if (iVar8 < 0x565) {
        if (iVar8 < 0x564) goto LAB_800aee9c;
        uVar7 = FUN_80022264(0x32,100);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_d4 = FLOAT_803e0220 * (float)(local_78 - DOUBLE_803e0390);
        local_108 = 0x2d;
        local_cc = (undefined *)0x80580210;
        local_b0 = 0xff;
        local_ce = 0xc0f;
      }
      else {
        if (iVar8 < 0x68b) goto LAB_800aee9c;
        if (param_3 == (short *)0x0) {
          uVar7 = FUN_80022264(0xfffffff9,7);
          local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_e0 = (float)(local_78 - DOUBLE_803e0390);
          uStack_7c = FUN_80022264(0xfffffff9,7);
          uStack_7c = uStack_7c ^ 0x80000000;
          local_80 = 0x43300000;
          local_d8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        }
        else {
          local_e0 = *(float *)(param_3 + 6) - *(float *)(puVar6 + 0xc);
          local_d8 = *(float *)(param_3 + 10) - *(float *)(puVar6 + 0x10);
        }
        local_dc = FLOAT_803e0178;
        uVar7 = FUN_80022264(0xffffffce,0x32);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_ec = FLOAT_803e0164 * (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0,0x32);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_e8 = FLOAT_803e0164 *
                   (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uStack_84 = FUN_80022264(0xffffffce,0x32);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        local_e4 = FLOAT_803e0164 *
                   (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
        local_d4 = FLOAT_803e0168;
        if (param_3 != (short *)0x0) {
          local_d4 = *(float *)(param_3 + 4);
        }
        local_108 = 0x32;
        local_b0 = 0x96;
        local_cc = (undefined *)0x80080200;
        local_ce = 0x62;
        uVar7 = FUN_80022264(0,0xffff);
        local_b8 = (ushort)uVar7;
        local_b6 = 0;
        local_b4 = 0;
        local_c4 = 0xffff;
        local_c0 = 0xffff;
        local_bc = 0;
        local_c8 = 0x1000020;
      }
    }
    else if (iVar8 == 0x68f) {
      uVar7 = FUN_80022264(0xfffffff9,7);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = (float)(local_78 - DOUBLE_803e0390);
      uStack_7c = FUN_80022264(0xfffffff9,7);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
      uStack_84 = FUN_80022264(0xfffffff9,7);
      uStack_84 = uStack_84 ^ 0x80000000;
      local_88 = 0x43300000;
      local_d8 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xffffffce,0x32);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_ec = FLOAT_803e0164 * (float)(local_90 - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xffffffce,0x32);
      local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e8 = FLOAT_803e0164 * (float)(local_98 - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xffffffce,0x32);
      local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e4 = FLOAT_803e0164 * (float)(local_a0 - DOUBLE_803e0390);
      local_d4 = FLOAT_803e0170;
      local_108 = 100;
      local_b0 = 0x96;
      local_cc = (undefined *)0x1080200;
      local_ce = 0x62;
      uVar7 = FUN_80022264(0,0xffff);
      local_b8 = (ushort)uVar7;
      local_b6 = 0;
      local_b4 = 0;
      local_c4 = 0xffff;
      local_c0 = 0xffff;
      local_bc = 0;
      local_c8 = 0x20;
    }
    else if (iVar8 < 0x68f) {
      if (iVar8 < 0x68e) {
        uVar7 = FUN_80022264(0xfffffff9,7);
        local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e0 = (float)(local_78 - DOUBLE_803e0390);
        uStack_7c = FUN_80022264(0xfffffff9,7);
        uStack_7c = uStack_7c ^ 0x80000000;
        local_80 = 0x43300000;
        local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
        uStack_84 = FUN_80022264(0xfffffff9,7);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        local_d8 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
        uVar7 = FUN_80022264(0xffffffce,0x32);
        local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_ec = FLOAT_803e0164 * (float)(local_90 - DOUBLE_803e0390);
        uVar7 = FUN_80022264(0xffffffce,0x32);
        local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e8 = FLOAT_803e0164 * (float)(local_98 - DOUBLE_803e0390);
        uVar7 = FUN_80022264(0xffffffce,0x32);
        local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        local_e4 = FLOAT_803e0164 * (float)(local_a0 - DOUBLE_803e0390);
        local_d4 = FLOAT_803e0168;
        local_108 = 0x5a;
        local_b0 = 0x96;
        local_cc = (undefined *)0x1080200;
        local_ce = 0x62;
        local_b8 = 0;
        local_b6 = 0;
        uVar7 = FUN_80022264(0,0xffff);
        local_b4 = (ushort)uVar7;
        local_c4 = 0x7fff;
        local_c0 = 0xffff;
        local_bc = 0xffff;
        local_c8 = 0x20;
      }
      else {
        local_d4 = FLOAT_803e016c;
        local_108 = 0x5f;
        local_cc = (undefined *)0x180208;
        local_ce = 0x62;
        uVar7 = FUN_80022264(0x8000,0xffff);
        local_b8 = (ushort)uVar7;
        local_b6 = 0;
        local_b4 = 0;
        local_c4 = FUN_80022264(0,0xffff);
        local_c0 = FUN_80022264(0,0x8000);
        local_bc = 0;
        local_c8 = 0x20;
      }
    }
    else {
      if (0x690 < iVar8) goto LAB_800aee9c;
      uVar7 = FUN_80022264(0xfffffff9,7);
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e0 = (float)(local_78 - DOUBLE_803e0390);
      uStack_7c = FUN_80022264(0xfffffff9,7);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      local_dc = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e0390);
      uStack_84 = FUN_80022264(0xfffffff9,7);
      uStack_84 = uStack_84 ^ 0x80000000;
      local_88 = 0x43300000;
      local_d8 = (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xffffffce,0x32);
      local_90 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_ec = FLOAT_803e0164 * (float)(local_90 - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0x14,0x32);
      local_98 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e8 = FLOAT_803e0174 * (float)(local_98 - DOUBLE_803e0390);
      uVar7 = FUN_80022264(0xffffffce,0x32);
      local_a0 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      local_e4 = FLOAT_803e0164 * (float)(local_a0 - DOUBLE_803e0390);
      local_d4 = FLOAT_803e0170;
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
LAB_800aedbc:
  local_cc = (undefined *)((uint)local_cc | param_4);
  if ((((uint)local_cc & 1) != 0) && (((uint)local_cc & 2) != 0)) {
    local_cc = (undefined *)((uint)local_cc ^ 2);
  }
  if (((uint)local_cc & 1) != 0) {
    if ((param_4 & 0x200000) == 0) {
      if (local_110 != (ushort *)0x0) {
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
  (**(code **)(*DAT_803dd6f8 + 8))(&local_110,0xffffffff,iVar8,0);
LAB_800aee9c:
  FUN_80286884();
  return;
}

