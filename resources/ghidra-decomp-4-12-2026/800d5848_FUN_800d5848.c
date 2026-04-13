// Function: FUN_800d5848
// Entry: 800d5848
// Size: 2500 bytes

/* WARNING: Removing unreachable block (ram,0x800d61ec) */
/* WARNING: Removing unreachable block (ram,0x800d61e4) */
/* WARNING: Removing unreachable block (ram,0x800d61dc) */
/* WARNING: Removing unreachable block (ram,0x800d61d4) */
/* WARNING: Removing unreachable block (ram,0x800d61cc) */
/* WARNING: Removing unreachable block (ram,0x800d61c4) */
/* WARNING: Removing unreachable block (ram,0x800d61bc) */
/* WARNING: Removing unreachable block (ram,0x800d61b4) */
/* WARNING: Removing unreachable block (ram,0x800d61ac) */
/* WARNING: Removing unreachable block (ram,0x800d61a4) */
/* WARNING: Removing unreachable block (ram,0x800d619c) */
/* WARNING: Removing unreachable block (ram,0x800d6194) */
/* WARNING: Removing unreachable block (ram,0x800d58b0) */
/* WARNING: Removing unreachable block (ram,0x800d58a8) */
/* WARNING: Removing unreachable block (ram,0x800d58a0) */
/* WARNING: Removing unreachable block (ram,0x800d5898) */
/* WARNING: Removing unreachable block (ram,0x800d5890) */
/* WARNING: Removing unreachable block (ram,0x800d5888) */
/* WARNING: Removing unreachable block (ram,0x800d5880) */
/* WARNING: Removing unreachable block (ram,0x800d5878) */
/* WARNING: Removing unreachable block (ram,0x800d5870) */
/* WARNING: Removing unreachable block (ram,0x800d5868) */
/* WARNING: Removing unreachable block (ram,0x800d5860) */
/* WARNING: Removing unreachable block (ram,0x800d5858) */

void FUN_800d5848(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6,float *param_7,uint param_8)

{
  uint uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double in_f20;
  double dVar16;
  double in_f21;
  double dVar17;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double dVar18;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar19;
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
  undefined8 uVar20;
  int aiStack_168 [2];
  undefined4 local_160;
  uint uStack_15c;
  undefined4 local_158;
  uint uStack_154;
  undefined4 local_150;
  uint uStack_14c;
  undefined4 local_148;
  uint uStack_144;
  undefined4 local_140;
  uint uStack_13c;
  undefined4 local_138;
  uint uStack_134;
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
  uVar20 = FUN_80286824();
  iVar3 = (int)((ulonglong)uVar20 >> 0x20);
  if (iVar3 != 0) {
    dVar15 = extraout_f1;
    iVar4 = FUN_800d57bc(*(uint *)(iVar3 + (int)uVar20 * 4 + 0x20),aiStack_168);
    if (iVar4 == 0) {
      iVar4 = FUN_800d57bc(*(uint *)(iVar3 + (1 - (int)uVar20) * 4 + 0x20),aiStack_168);
    }
    if (iVar4 != 0) {
      uStack_15c = (uint)*(byte *)(iVar3 + 0x29) << 8 ^ 0x80000000;
      local_160 = 0x43300000;
      dVar9 = (double)FUN_802945e0();
      dVar9 = -dVar9;
      uStack_154 = (uint)*(byte *)(iVar3 + 0x29) << 8 ^ 0x80000000;
      local_158 = 0x43300000;
      dVar10 = (double)FUN_80294964();
      dVar10 = -dVar10;
      uStack_14c = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
      local_150 = 0x43300000;
      dVar11 = (double)FUN_802945e0();
      dVar11 = -dVar11;
      uStack_144 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
      local_148 = 0x43300000;
      dVar12 = (double)FUN_80294964();
      dVar14 = DOUBLE_803e1170;
      dVar12 = -dVar12;
      uStack_13c = (uint)*(byte *)(iVar3 + 0x2a);
      local_140 = 0x43300000;
      dVar17 = (double)(FLOAT_803e1160 *
                       (float)((double)CONCAT44(0x43300000,uStack_13c) - DOUBLE_803e1178));
      uStack_134 = (uint)*(byte *)(iVar4 + 0x2a);
      local_138 = 0x43300000;
      dVar16 = (double)(FLOAT_803e1160 *
                       (float)((double)CONCAT44(0x43300000,uStack_134) - DOUBLE_803e1178));
      uVar1 = param_8 & 0xff;
      if (uVar1 == 1) {
        iVar5 = 0;
        iVar8 = 0;
        dVar18 = (double)(float)(dVar17 * dVar10);
        dVar12 = (double)(float)(dVar16 * dVar12);
        dVar10 = (double)(float)(dVar17 * -dVar9);
        dVar9 = (double)(float)(dVar16 * -dVar11);
        dVar11 = (double)FLOAT_803e1164;
        dVar19 = (double)FLOAT_803e1168;
        dVar15 = DOUBLE_803e1178;
        do {
          iVar7 = iVar3 + iVar8;
          uStack_134 = (int)*(char *)(iVar7 + 0x2d) ^ 0x80000000;
          local_138 = 0x43300000;
          *param_5 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_134) - dVar14) *
                             dVar18 + (double)*(float *)(iVar3 + 8));
          iVar6 = iVar4 + iVar8;
          uStack_13c = (int)*(char *)(iVar6 + 0x2d) ^ 0x80000000;
          local_140 = 0x43300000;
          param_5[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_13c) - dVar14) *
                               dVar12 + (double)*(float *)(iVar4 + 8));
          uStack_144 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
          local_148 = 0x43300000;
          dVar13 = (double)FUN_802945e0();
          uStack_14c = (uint)*(byte *)(iVar3 + 0x3d);
          local_150 = 0x43300000;
          param_5[2] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_14c)
                                                                       - dVar15) * dVar13));
          uStack_154 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
          local_158 = 0x43300000;
          dVar13 = (double)FUN_802945e0();
          uStack_15c = (uint)*(byte *)(iVar4 + 0x3d);
          local_160 = 0x43300000;
          param_5[3] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_15c)
                                                                       - dVar15) * dVar13));
          uStack_12c = (int)*(char *)(iVar7 + 0x31) ^ 0x80000000;
          local_130 = 0x43300000;
          *param_6 = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                                     dVar14) + (double)*(float *)(iVar3 + 0xc));
          uStack_124 = (int)*(char *)(iVar6 + 0x31) ^ 0x80000000;
          local_128 = 0x43300000;
          param_6[1] = (float)(dVar16 * (double)(float)((double)CONCAT44(0x43300000,uStack_124) -
                                                       dVar14) + (double)*(float *)(iVar4 + 0xc));
          param_6[2] = (float)dVar19;
          param_6[3] = (float)dVar19;
          uStack_11c = (int)*(char *)(iVar7 + 0x2d) ^ 0x80000000;
          local_120 = 0x43300000;
          *param_7 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) - dVar14) *
                             dVar10 + (double)*(float *)(iVar3 + 0x10));
          uStack_114 = (int)*(char *)(iVar6 + 0x2d) ^ 0x80000000;
          local_118 = 0x43300000;
          param_7[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_114) - dVar14) *
                               dVar9 + (double)*(float *)(iVar4 + 0x10));
          uStack_10c = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
          local_110 = 0x43300000;
          dVar13 = (double)FUN_80294964();
          uStack_104 = (uint)*(byte *)(iVar3 + 0x3d);
          local_108 = 0x43300000;
          param_7[2] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_104)
                                                                       - dVar15) * dVar13));
          uStack_fc = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
          local_100 = 0x43300000;
          dVar13 = (double)FUN_80294964();
          uStack_f4 = (uint)*(byte *)(iVar4 + 0x3d);
          local_f8 = 0x43300000;
          param_7[3] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_f4)
                                                                       - dVar15) * dVar13));
          iVar8 = iVar8 + 1;
          param_5 = param_5 + 4;
          param_6 = param_6 + 4;
          param_7 = param_7 + 4;
          iVar5 = iVar5 + 4;
        } while (iVar5 < 0x10);
      }
      else if (uVar1 == 0) {
        *param_5 = (float)(dVar15 * (double)(float)(dVar17 * dVar10) + (double)*(float *)(iVar3 + 8)
                          );
        param_5[1] = (float)(dVar15 * (double)(float)(dVar16 * dVar12) +
                            (double)*(float *)(iVar4 + 8));
        uStack_f4 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar14 = (double)FUN_802945e0();
        uStack_fc = (uint)*(byte *)(iVar3 + 0x3d);
        local_100 = 0x43300000;
        param_5[2] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_fc) -
                                            DOUBLE_803e1178) * dVar14);
        uStack_104 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_108 = 0x43300000;
        dVar14 = (double)FUN_802945e0();
        uStack_10c = (uint)*(byte *)(iVar4 + 0x3d);
        local_110 = 0x43300000;
        param_5[3] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_10c) -
                                            DOUBLE_803e1178) * dVar14);
        *param_6 = (float)(dVar17 * param_2 + (double)*(float *)(iVar3 + 0xc));
        param_6[1] = (float)(dVar16 * param_2 + (double)*(float *)(iVar4 + 0xc));
        fVar2 = FLOAT_803e1168;
        param_6[2] = FLOAT_803e1168;
        param_6[3] = fVar2;
        *param_7 = (float)(dVar15 * (double)(float)(dVar17 * -dVar9) +
                          (double)*(float *)(iVar3 + 0x10));
        param_7[1] = (float)(dVar15 * (double)(float)(dVar16 * -dVar11) +
                            (double)*(float *)(iVar4 + 0x10));
        uStack_114 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_118 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_11c = (uint)*(byte *)(iVar3 + 0x3d);
        local_120 = 0x43300000;
        param_7[2] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                            DOUBLE_803e1178) * dVar15);
        uStack_124 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_128 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_12c = (uint)*(byte *)(iVar4 + 0x3d);
        local_130 = 0x43300000;
        param_7[3] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                            DOUBLE_803e1178) * dVar15);
      }
      else {
        iVar5 = iVar3 + (uVar1 - 2);
        uStack_f4 = (int)*(char *)(iVar5 + 0x2d) ^ 0x80000000;
        local_f8 = 0x43300000;
        *param_5 = (float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803e1170) *
                   (float)(dVar17 * dVar10) + *(float *)(iVar3 + 8);
        iVar8 = iVar4 + (uVar1 - 2);
        uStack_fc = (int)*(char *)(iVar8 + 0x2d) ^ 0x80000000;
        local_100 = 0x43300000;
        param_5[1] = (float)((double)CONCAT44(0x43300000,uStack_fc) - dVar14) *
                     (float)(dVar16 * dVar12) + *(float *)(iVar4 + 8);
        uStack_104 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_108 = 0x43300000;
        dVar15 = (double)FUN_802945e0();
        uStack_10c = (uint)*(byte *)(iVar3 + 0x3d);
        local_110 = 0x43300000;
        param_5[2] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_10c) -
                                            DOUBLE_803e1178) * dVar15);
        uStack_114 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_118 = 0x43300000;
        dVar15 = (double)FUN_802945e0();
        uStack_11c = (uint)*(byte *)(iVar4 + 0x3d);
        local_120 = 0x43300000;
        param_5[3] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                            DOUBLE_803e1178) * dVar15);
        dVar15 = DOUBLE_803e1170;
        uStack_124 = (int)*(char *)(iVar5 + 0x31) ^ 0x80000000;
        local_128 = 0x43300000;
        *param_6 = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack_124) -
                                                   DOUBLE_803e1170) +
                          (double)*(float *)(iVar3 + 0xc));
        uStack_12c = (int)*(char *)(iVar8 + 0x31) ^ 0x80000000;
        local_130 = 0x43300000;
        param_6[1] = (float)(dVar16 * (double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                                     dVar15) + (double)*(float *)(iVar4 + 0xc));
        fVar2 = FLOAT_803e1168;
        param_6[2] = FLOAT_803e1168;
        param_6[3] = fVar2;
        uStack_134 = (int)*(char *)(iVar5 + 0x2d) ^ 0x80000000;
        local_138 = 0x43300000;
        *param_7 = (float)((double)CONCAT44(0x43300000,uStack_134) - dVar15) *
                   (float)(dVar17 * -dVar9) + *(float *)(iVar3 + 0x10);
        uStack_13c = (int)*(char *)(iVar8 + 0x2d) ^ 0x80000000;
        local_140 = 0x43300000;
        param_7[1] = (float)((double)CONCAT44(0x43300000,uStack_13c) - dVar15) *
                     (float)(dVar16 * -dVar11) + *(float *)(iVar4 + 0x10);
        uStack_144 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_148 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_14c = (uint)*(byte *)(iVar3 + 0x3d);
        local_150 = 0x43300000;
        param_7[2] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_14c) -
                                            DOUBLE_803e1178) * dVar15);
        uStack_154 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_158 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_15c = (uint)*(byte *)(iVar4 + 0x3d);
        local_160 = 0x43300000;
        param_7[3] = FLOAT_803e1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_15c) -
                                            DOUBLE_803e1178) * dVar15);
      }
    }
  }
  FUN_80286870();
  return;
}

