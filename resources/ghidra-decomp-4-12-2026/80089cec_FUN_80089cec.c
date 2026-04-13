// Function: FUN_80089cec
// Entry: 80089cec
// Size: 1516 bytes

void FUN_80089cec(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,uint param_7,int param_8,int param_9,
                 undefined param_10)

{
  int iVar1;
  int iVar2;
  float fVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  int iVar7;
  float *pfVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  undefined uVar12;
  undefined uVar13;
  undefined uVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  uint uVar18;
  double extraout_f1;
  undefined8 uVar19;
  float local_178;
  float local_174;
  float local_170;
  undefined4 local_168;
  uint uStack_164;
  undefined4 local_160;
  uint uStack_15c;
  undefined4 local_158;
  uint uStack_154;
  longlong local_150;
  undefined4 local_148;
  uint uStack_144;
  undefined4 local_140;
  uint uStack_13c;
  undefined4 local_138;
  uint uStack_134;
  longlong local_130;
  undefined4 local_128;
  uint uStack_124;
  undefined4 local_120;
  uint uStack_11c;
  undefined4 local_118;
  uint uStack_114;
  longlong local_110;
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  longlong local_d0;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  longlong local_b0;
  undefined4 local_a8;
  uint uStack_a4;
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  undefined8 local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined8 local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  
  uVar19 = FUN_80286834();
  iVar7 = (int)((ulonglong)uVar19 >> 0x20);
  uVar18 = (uint)uVar19;
  local_178 = (float)-extraout_f1;
  local_174 = (float)-param_2;
  local_170 = (float)-param_3;
  if (iVar7 == 2) {
    iVar15 = DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x24d) * 0xa4 + 0x20;
    iVar16 = DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x24c) * 0xa4 + 0x20;
    fVar3 = *(float *)(DAT_803dddac + 0x244);
    local_178 = fVar3 * (*(float *)(iVar16 + 0x70) - *(float *)(iVar15 + 0x70)) +
                *(float *)(iVar15 + 0x70);
    local_174 = fVar3 * (*(float *)(iVar16 + 0x74) - *(float *)(iVar15 + 0x74)) +
                *(float *)(iVar15 + 0x74);
    local_170 = fVar3 * (*(float *)(iVar16 + 0x78) - *(float *)(iVar15 + 0x78)) +
                *(float *)(iVar15 + 0x78);
    uStack_15c = (uint)*(byte *)(iVar15 + 0x58);
    uStack_164 = (uint)*(byte *)(iVar16 + 0x58);
    local_168 = 0x43300000;
    local_160 = 0x43300000;
    local_158 = 0x43300000;
    uVar18 = (uint)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_164) - DOUBLE_803dfcf0) -
                            (float)((double)CONCAT44(0x43300000,uStack_15c) - DOUBLE_803dfcf0)) +
                   (float)((double)CONCAT44(0x43300000,uStack_15c) - DOUBLE_803dfcf0));
    local_150 = (longlong)(int)uVar18;
    uStack_13c = (uint)*(byte *)(iVar15 + 0x59);
    uStack_144 = (uint)*(byte *)(iVar16 + 0x59);
    local_148 = 0x43300000;
    local_140 = 0x43300000;
    local_138 = 0x43300000;
    param_6 = (uint)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_144) - DOUBLE_803dfcf0) -
                             (float)((double)CONCAT44(0x43300000,uStack_13c) - DOUBLE_803dfcf0)) +
                    (float)((double)CONCAT44(0x43300000,uStack_13c) - DOUBLE_803dfcf0));
    local_130 = (longlong)(int)param_6;
    uStack_11c = (uint)*(byte *)(iVar15 + 0x5a);
    uStack_124 = (uint)*(byte *)(iVar16 + 0x5a);
    local_128 = 0x43300000;
    local_120 = 0x43300000;
    local_118 = 0x43300000;
    param_7 = (uint)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803dfcf0) -
                             (float)((double)CONCAT44(0x43300000,uStack_11c) - DOUBLE_803dfcf0)) +
                    (float)((double)CONCAT44(0x43300000,uStack_11c) - DOUBLE_803dfcf0));
    local_110 = (longlong)(int)param_7;
    uStack_fc = (uint)*(byte *)(iVar15 + 0x60);
    uStack_104 = (uint)*(byte *)(iVar16 + 0x60);
    local_108 = 0x43300000;
    local_100 = 0x43300000;
    local_f8 = 0x43300000;
    uVar9 = (uint)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_104) - DOUBLE_803dfcf0) -
                           (float)((double)CONCAT44(0x43300000,uStack_fc) - DOUBLE_803dfcf0)) +
                  (float)((double)CONCAT44(0x43300000,uStack_fc) - DOUBLE_803dfcf0));
    local_f0 = (longlong)(int)uVar9;
    uStack_dc = (uint)*(byte *)(iVar15 + 0x61);
    uStack_e4 = (uint)*(byte *)(iVar16 + 0x61);
    local_e8 = 0x43300000;
    local_e0 = 0x43300000;
    local_d8 = 0x43300000;
    uVar10 = (uint)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803dfcf0) -
                            (float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803dfcf0)) +
                   (float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803dfcf0));
    local_d0 = (longlong)(int)uVar10;
    uStack_bc = (uint)*(byte *)(iVar15 + 0x62);
    uStack_c4 = (uint)*(byte *)(iVar16 + 0x62);
    local_c8 = 0x43300000;
    local_c0 = 0x43300000;
    local_b8 = 0x43300000;
    uVar11 = (uint)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803dfcf0) -
                            (float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803dfcf0)) +
                   (float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803dfcf0));
    local_b0 = (longlong)(int)uVar11;
    uStack_9c = (uint)*(byte *)(iVar15 + 0x68);
    uStack_a4 = (uint)*(byte *)(iVar16 + 0x68);
    local_a8 = 0x43300000;
    local_a0 = 0x43300000;
    local_98 = 0x43300000;
    iVar17 = (int)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803dfcf0) -
                           (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803dfcf0)) +
                  (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803dfcf0));
    local_90._7_1_ = (undefined)iVar17;
    uStack_7c = (uint)*(byte *)(iVar15 + 0x69);
    uStack_84 = (uint)*(byte *)(iVar16 + 0x69);
    local_88 = 0x43300000;
    local_80 = 0x43300000;
    local_78 = 0x43300000;
    iVar1 = (int)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803dfcf0) -
                          (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803dfcf0)) +
                 (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803dfcf0));
    local_70._7_1_ = (undefined)iVar1;
    uStack_5c = (uint)*(byte *)(iVar15 + 0x6a);
    uStack_64 = (uint)*(byte *)(iVar16 + 0x6a);
    local_68 = 0x43300000;
    local_60 = 0x43300000;
    local_58 = 0x43300000;
    iVar2 = (int)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803dfcf0) -
                          (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803dfcf0)) +
                 (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803dfcf0));
    local_50._7_1_ = (undefined)iVar2;
    uStack_3c = (uint)*(byte *)(iVar15 + 0xa0);
    uStack_44 = (uint)*(byte *)(iVar16 + 0xa0);
    local_48 = 0x43300000;
    local_40 = 0x43300000;
    local_38 = 0x43300000;
    iVar15 = (int)(fVar3 * ((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803dfcf0) -
                           (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803dfcf0)) +
                  (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803dfcf0));
    local_30 = (longlong)iVar15;
    param_10 = (undefined)iVar15;
    uStack_154 = uStack_15c;
    uStack_134 = uStack_13c;
    uStack_114 = uStack_11c;
    uStack_f4 = uStack_fc;
    uStack_d4 = uStack_dc;
    uStack_b4 = uStack_bc;
    uStack_94 = uStack_9c;
    lVar4 = (longlong)iVar17;
    uStack_74 = uStack_7c;
    lVar5 = (longlong)iVar1;
    uStack_54 = uStack_5c;
    lVar6 = (longlong)iVar2;
    uStack_34 = uStack_3c;
    uVar12 = (undefined)local_90;
    uVar13 = (undefined)local_70;
    uVar14 = (undefined)local_50;
  }
  else {
    iVar17 = iVar7 * 0xa4;
    if (*(char *)(DAT_803dddac + iVar17 + 0xc1) < '\0') {
      local_178 = FLOAT_803dfcec;
      local_174 = FLOAT_803dfcec;
      local_170 = FLOAT_803dfcec;
      FUN_80247ef8(&local_178,&local_178);
      pfVar8 = (float *)FUN_8000f578();
      FUN_80247cd8(pfVar8,&local_178,&local_178);
    }
    lVar4 = local_90;
    lVar5 = local_70;
    lVar6 = local_50;
    if ((*(byte *)(DAT_803dddac + iVar17 + 0xc1) >> 6 & 1) == 0) {
      iVar17 = param_8 + 1;
      uVar9 = (int)(uVar18 * iVar17) >> 8;
      uVar10 = (int)(param_6 * iVar17) >> 8;
      uVar11 = (int)(param_7 * iVar17) >> 8;
      iVar17 = param_9 + 1;
      uVar12 = (undefined)(uVar18 * iVar17 >> 8);
      uVar13 = (undefined)(param_6 * iVar17 >> 8);
      uVar14 = (undefined)(param_7 * iVar17 >> 8);
    }
    else {
      iVar17 = DAT_803dddac + iVar17;
      local_178 = *(float *)(iVar17 + 0xa8);
      local_174 = *(float *)(iVar17 + 0xac);
      local_170 = *(float *)(iVar17 + 0xb0);
      uVar18 = (uint)*(byte *)(iVar17 + 0x7c);
      param_6 = (uint)*(byte *)(iVar17 + 0x7d);
      param_7 = (uint)*(byte *)(iVar17 + 0x7e);
      uVar9 = (uint)*(byte *)(iVar17 + 0x84);
      uVar10 = (uint)*(byte *)(iVar17 + 0x85);
      uVar11 = (uint)*(byte *)(iVar17 + 0x86);
      uVar12 = *(undefined *)(iVar17 + 0x8c);
      uVar13 = *(undefined *)(iVar17 + 0x8d);
      uVar14 = *(undefined *)(iVar17 + 0x8e);
      param_10 = 0xff;
    }
  }
  local_50 = lVar6;
  local_70 = lVar5;
  local_90 = lVar4;
  iVar7 = iVar7 * 0xa4;
  *(float *)(DAT_803dddac + iVar7 + 0x90) = local_178;
  *(float *)(DAT_803dddac + iVar7 + 0x94) = local_174;
  *(float *)(DAT_803dddac + iVar7 + 0x98) = local_170;
  *(char *)(DAT_803dddac + iVar7 + 0x78) = (char)uVar18;
  *(char *)(DAT_803dddac + iVar7 + 0x79) = (char)param_6;
  *(char *)(DAT_803dddac + iVar7 + 0x7a) = (char)param_7;
  *(float *)(DAT_803dddac + iVar7 + 0x9c) = -local_178;
  *(float *)(DAT_803dddac + iVar7 + 0xa0) = -local_174;
  *(float *)(DAT_803dddac + iVar7 + 0xa4) = -local_170;
  *(char *)(DAT_803dddac + iVar7 + 0x80) = (char)(uVar9 * (DAT_803dc294 + 1) >> 8);
  *(char *)(DAT_803dddac + iVar7 + 0x81) = (char)(uVar10 * (DAT_803dc294 + 1) >> 8);
  *(char *)(DAT_803dddac + iVar7 + 0x82) = (char)(uVar11 * (DAT_803dc294 + 1) >> 8);
  *(undefined *)(DAT_803dddac + iVar7 + 0x88) = uVar12;
  *(undefined *)(DAT_803dddac + iVar7 + 0x89) = uVar13;
  *(undefined *)(DAT_803dddac + iVar7 + 0x8a) = uVar14;
  *(undefined *)(DAT_803dddac + iVar7 + 0xc0) = param_10;
  FUN_80286880();
  return;
}

