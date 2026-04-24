// Function: FUN_800a3d7c
// Entry: 800a3d7c
// Size: 1552 bytes

/* WARNING: Removing unreachable block (ram,0x800a436c) */
/* WARNING: Removing unreachable block (ram,0x800a4364) */
/* WARNING: Removing unreachable block (ram,0x800a435c) */
/* WARNING: Removing unreachable block (ram,0x800a4354) */
/* WARNING: Removing unreachable block (ram,0x800a434c) */
/* WARNING: Removing unreachable block (ram,0x800a4344) */
/* WARNING: Removing unreachable block (ram,0x800a433c) */
/* WARNING: Removing unreachable block (ram,0x800a4334) */
/* WARNING: Removing unreachable block (ram,0x800a432c) */
/* WARNING: Removing unreachable block (ram,0x800a4324) */
/* WARNING: Removing unreachable block (ram,0x800a431c) */
/* WARNING: Removing unreachable block (ram,0x800a4314) */
/* WARNING: Removing unreachable block (ram,0x800a3de4) */
/* WARNING: Removing unreachable block (ram,0x800a3ddc) */
/* WARNING: Removing unreachable block (ram,0x800a3dd4) */
/* WARNING: Removing unreachable block (ram,0x800a3dcc) */
/* WARNING: Removing unreachable block (ram,0x800a3dc4) */
/* WARNING: Removing unreachable block (ram,0x800a3dbc) */
/* WARNING: Removing unreachable block (ram,0x800a3db4) */
/* WARNING: Removing unreachable block (ram,0x800a3dac) */
/* WARNING: Removing unreachable block (ram,0x800a3da4) */
/* WARNING: Removing unreachable block (ram,0x800a3d9c) */
/* WARNING: Removing unreachable block (ram,0x800a3d94) */
/* WARNING: Removing unreachable block (ram,0x800a3d8c) */

void FUN_800a3d7c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)

{
  char cVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  undefined2 *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double extraout_f1;
  double in_f20;
  double dVar10;
  double in_f21;
  double in_f22;
  double dVar11;
  double dVar12;
  double in_f23;
  double dVar13;
  double dVar14;
  double in_f24;
  double dVar15;
  double dVar16;
  double in_f25;
  double dVar17;
  double in_f26;
  double dVar18;
  double in_f27;
  double dVar19;
  double in_f28;
  double dVar20;
  double in_f29;
  double dVar21;
  double in_f30;
  double dVar22;
  double in_f31;
  double dVar23;
  double in_ps20_1;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar24;
  undefined2 local_148;
  undefined2 local_146;
  undefined2 local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
  undefined4 local_130;
  uint uStack_12c;
  undefined4 local_128;
  uint uStack_124;
  undefined4 local_120;
  uint uStack_11c;
  undefined4 local_118;
  uint uStack_114;
  undefined4 local_110;
  uint uStack_10c;
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  float local_b8;
  float fStack_b4;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
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
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  uVar24 = FUN_80286840();
  iVar9 = (int)((ulonglong)uVar24 >> 0x20);
  iVar7 = (int)uVar24;
  bVar4 = false;
  dVar10 = extraout_f1;
  puVar5 = FUN_8000facc();
  DAT_803ddf1c = puVar5[1];
  DAT_803ddf1a = *puVar5;
  dVar11 = (double)(*(float *)(puVar5 + 6) - *(float *)(param_5 + 0xc));
  dVar13 = (double)(*(float *)(puVar5 + 8) - *(float *)(param_5 + 0x10));
  dVar15 = (double)(*(float *)(puVar5 + 10) - *(float *)(param_5 + 0x14));
  for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
    cVar1 = *(char *)(iVar9 + iVar8 * 0x4c + 0x48);
    if ((((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) || ((byte)(cVar1 - 0x14U) < 2)) ||
       (cVar1 == '\x17')) {
      DAT_803109a8 = (float)dVar11;
      DAT_803109ac = (float)dVar13;
      DAT_803109b0 = (float)dVar15;
      dVar12 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                           (double)(float)(dVar11 * dVar11 +
                                                          (double)(float)(dVar13 * dVar13))));
      dVar14 = (double)(float)((double)FLOAT_803e00e8 * dVar12);
      if ((double)FLOAT_803e00ec != dVar12) {
        dVar11 = (double)(float)(dVar11 / dVar12);
        dVar13 = (double)(float)(dVar13 / dVar12);
        dVar15 = (double)(float)(dVar15 / dVar12);
      }
      dVar11 = (double)(float)(dVar11 * dVar14);
      dVar13 = (double)(float)(dVar13 * dVar14);
      dVar15 = (double)(float)(dVar15 * dVar14);
      local_13c = FLOAT_803e00ec;
      local_138 = FLOAT_803e00ec;
      local_134 = FLOAT_803e00ec;
      local_140 = FLOAT_803e00f0;
      local_144 = 0;
      local_146 = 0;
      local_148 = 0;
      bVar4 = true;
      iVar8 = iVar7;
    }
  }
  if (bVar4) {
    for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
      cVar1 = *(char *)(iVar9 + 0x48);
      if (((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) ||
         (((byte)(cVar1 - 0x14U) < 2 || (cVar1 == '\x17')))) {
        fVar2 = *(float *)(param_5 + 0xc);
        uStack_12c = (int)*(short *)(iVar9 + 0x10) ^ 0x80000000;
        local_130 = 0x43300000;
        dVar23 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_124 = (int)*(short *)(iVar9 + 0x16) ^ 0x80000000;
        local_128 = 0x43300000;
        dVar22 = (double)(float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803e0100);
        fVar3 = *(float *)(param_5 + 0x14);
        uStack_11c = (int)*(short *)(iVar9 + 0x1c) ^ 0x80000000;
        local_120 = 0x43300000;
        dVar21 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_114 = (int)*(short *)(iVar9 + 0x12) ^ 0x80000000;
        local_118 = 0x43300000;
        dVar20 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_114) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_10c = (int)*(short *)(iVar9 + 0x18) ^ 0x80000000;
        local_110 = 0x43300000;
        dVar19 = (double)(float)((double)CONCAT44(0x43300000,uStack_10c) - DOUBLE_803e0100);
        uStack_104 = (int)*(short *)(iVar9 + 0x1e) ^ 0x80000000;
        local_108 = 0x43300000;
        dVar18 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_104) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_fc = (int)*(short *)(iVar9 + 0x14) ^ 0x80000000;
        local_100 = 0x43300000;
        dVar17 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_fc) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_f4 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803e0100);
        uStack_ec = (int)*(short *)(iVar9 + 0x20) ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar14 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_ec) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_e4 = FUN_80022264(1,1000);
        uStack_e4 = uStack_e4 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar12 = (double)((float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803e0100) /
                         FLOAT_803e00f4);
        uStack_dc = FUN_80022264(1,1000);
        uStack_dc = uStack_dc ^ 0x80000000;
        local_e0 = 0x43300000;
        dVar11 = FUN_80293900((double)((float)((double)CONCAT44(0x43300000,uStack_dc) -
                                              DOUBLE_803e0100) / FLOAT_803e00f4));
        dVar13 = (double)(float)((double)FLOAT_803e00f0 - dVar11);
        dVar15 = (double)(float)((double)(float)((double)FLOAT_803e00f0 - dVar12) * dVar11);
        dVar11 = (double)(float)(dVar12 * dVar11);
        local_13c = (float)(dVar11 * dVar17 +
                           (double)(float)(dVar13 * dVar23 + (double)(float)(dVar15 * dVar20)));
        local_134 = (float)(dVar11 * dVar14 +
                           (double)(float)(dVar13 * dVar21 + (double)(float)(dVar15 * dVar18)));
        local_138 = (float)(dVar11 * dVar16 +
                           (double)(float)(dVar13 * dVar22 + (double)(float)(dVar15 * dVar19))) +
                    FLOAT_803e00f8;
        cVar1 = *(char *)(iVar9 + 0x48);
        if ((cVar1 == '\x12') || (cVar1 == '\x10')) {
          uVar6 = FUN_80022264(0,0x1e);
          if (uVar6 == 1) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x72,&local_148,0x200001,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x11') {
          uVar6 = FUN_80022264(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x14') {
          uVar6 = FUN_80022264(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x15') {
          uVar6 = FUN_80022264(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x17') {
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
        }
      }
      iVar9 = iVar9 + 0x4c;
    }
  }
  FUN_8028688c();
  return;
}

