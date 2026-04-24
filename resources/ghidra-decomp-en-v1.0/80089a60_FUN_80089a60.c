// Function: FUN_80089a60
// Entry: 80089a60
// Size: 1516 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_80089a60(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,uint param_7,int param_8,int param_9,
                 undefined param_10)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  double extraout_f1;
  undefined8 uVar11;
  float local_178;
  float local_174;
  float local_170;
  undefined4 local_168;
  uint uStack356;
  undefined4 local_160;
  uint uStack348;
  undefined4 local_158;
  uint uStack340;
  longlong local_150;
  undefined4 local_148;
  uint uStack324;
  undefined4 local_140;
  uint uStack316;
  undefined4 local_138;
  uint uStack308;
  longlong local_130;
  undefined4 local_128;
  uint uStack292;
  undefined4 local_120;
  uint uStack284;
  undefined4 local_118;
  uint uStack276;
  longlong local_110;
  undefined4 local_108;
  uint uStack260;
  undefined4 local_100;
  uint uStack252;
  undefined4 local_f8;
  uint uStack244;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  longlong local_d0;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  longlong local_b0;
  undefined4 local_a8;
  uint uStack164;
  undefined4 local_a0;
  uint uStack156;
  undefined4 local_98;
  uint uStack148;
  undefined8 local_90;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined8 local_70;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  
  uVar11 = FUN_802860d0();
  iVar2 = (int)((ulonglong)uVar11 >> 0x20);
  uVar10 = (uint)uVar11;
  local_178 = (float)-extraout_f1;
  local_174 = (float)-param_2;
  local_170 = (float)-param_3;
  if (iVar2 == 2) {
    iVar7 = DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x24d) * 0xa4 + 0x20;
    iVar8 = DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x24c) * 0xa4 + 0x20;
    fVar1 = *(float *)(DAT_803dd12c + 0x244);
    local_178 = fVar1 * (*(float *)(iVar8 + 0x70) - *(float *)(iVar7 + 0x70)) +
                *(float *)(iVar7 + 0x70);
    local_174 = fVar1 * (*(float *)(iVar8 + 0x74) - *(float *)(iVar7 + 0x74)) +
                *(float *)(iVar7 + 0x74);
    local_170 = fVar1 * (*(float *)(iVar8 + 0x78) - *(float *)(iVar7 + 0x78)) +
                *(float *)(iVar7 + 0x78);
    uStack348 = (uint)*(byte *)(iVar7 + 0x58);
    uStack356 = (uint)*(byte *)(iVar8 + 0x58);
    local_168 = 0x43300000;
    local_160 = 0x43300000;
    local_158 = 0x43300000;
    uVar10 = (uint)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack356) - DOUBLE_803df070) -
                            (float)((double)CONCAT44(0x43300000,uStack348) - DOUBLE_803df070)) +
                   (float)((double)CONCAT44(0x43300000,uStack348) - DOUBLE_803df070));
    local_150 = (longlong)(int)uVar10;
    uStack316 = (uint)*(byte *)(iVar7 + 0x59);
    uStack324 = (uint)*(byte *)(iVar8 + 0x59);
    local_148 = 0x43300000;
    local_140 = 0x43300000;
    local_138 = 0x43300000;
    param_6 = (uint)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack324) - DOUBLE_803df070) -
                             (float)((double)CONCAT44(0x43300000,uStack316) - DOUBLE_803df070)) +
                    (float)((double)CONCAT44(0x43300000,uStack316) - DOUBLE_803df070));
    local_130 = (longlong)(int)param_6;
    uStack284 = (uint)*(byte *)(iVar7 + 0x5a);
    uStack292 = (uint)*(byte *)(iVar8 + 0x5a);
    local_128 = 0x43300000;
    local_120 = 0x43300000;
    local_118 = 0x43300000;
    param_7 = (uint)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack292) - DOUBLE_803df070) -
                             (float)((double)CONCAT44(0x43300000,uStack284) - DOUBLE_803df070)) +
                    (float)((double)CONCAT44(0x43300000,uStack284) - DOUBLE_803df070));
    local_110 = (longlong)(int)param_7;
    uStack252 = (uint)*(byte *)(iVar7 + 0x60);
    uStack260 = (uint)*(byte *)(iVar8 + 0x60);
    local_108 = 0x43300000;
    local_100 = 0x43300000;
    local_f8 = 0x43300000;
    uVar4 = (uint)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack260) - DOUBLE_803df070) -
                           (float)((double)CONCAT44(0x43300000,uStack252) - DOUBLE_803df070)) +
                  (float)((double)CONCAT44(0x43300000,uStack252) - DOUBLE_803df070));
    local_f0 = (longlong)(int)uVar4;
    uStack220 = (uint)*(byte *)(iVar7 + 0x61);
    uStack228 = (uint)*(byte *)(iVar8 + 0x61);
    local_e8 = 0x43300000;
    local_e0 = 0x43300000;
    local_d8 = 0x43300000;
    uVar5 = (uint)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803df070) -
                           (float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803df070)) +
                  (float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803df070));
    local_d0 = (longlong)(int)uVar5;
    uStack188 = (uint)*(byte *)(iVar7 + 0x62);
    uStack196 = (uint)*(byte *)(iVar8 + 0x62);
    local_c8 = 0x43300000;
    local_c0 = 0x43300000;
    local_b8 = 0x43300000;
    uVar6 = (uint)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803df070) -
                           (float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803df070)) +
                  (float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803df070));
    local_b0 = (longlong)(int)uVar6;
    uStack156 = (uint)*(byte *)(iVar7 + 0x68);
    uStack164 = (uint)*(byte *)(iVar8 + 0x68);
    local_a8 = 0x43300000;
    local_a0 = 0x43300000;
    local_98 = 0x43300000;
    iVar9 = (int)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803df070) -
                          (float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803df070)) +
                 (float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803df070));
    local_90 = (longlong)iVar9;
    local_90._7_1_ = (undefined)iVar9;
    uStack124 = (uint)*(byte *)(iVar7 + 0x69);
    uStack132 = (uint)*(byte *)(iVar8 + 0x69);
    local_88 = 0x43300000;
    local_80 = 0x43300000;
    local_78 = 0x43300000;
    iVar9 = (int)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df070) -
                          (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df070)) +
                 (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df070));
    local_70 = (longlong)iVar9;
    local_70._7_1_ = (undefined)iVar9;
    uStack92 = (uint)*(byte *)(iVar7 + 0x6a);
    uStack100 = (uint)*(byte *)(iVar8 + 0x6a);
    local_68 = 0x43300000;
    local_60 = 0x43300000;
    local_58 = 0x43300000;
    iVar9 = (int)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803df070) -
                          (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df070)) +
                 (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df070));
    local_50 = (longlong)iVar9;
    local_50._7_1_ = (undefined)iVar9;
    uStack60 = (uint)*(byte *)(iVar7 + 0xa0);
    uStack68 = (uint)*(byte *)(iVar8 + 0xa0);
    local_48 = 0x43300000;
    local_40 = 0x43300000;
    local_38 = 0x43300000;
    iVar9 = (int)(fVar1 * ((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df070) -
                          (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df070)) +
                 (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df070));
    local_30 = (longlong)iVar9;
    param_10 = (undefined)iVar9;
    uStack340 = uStack348;
    uStack308 = uStack316;
    uStack276 = uStack284;
    uStack244 = uStack252;
    uStack212 = uStack220;
    uStack180 = uStack188;
    uStack148 = uStack156;
    uStack116 = uStack124;
    uStack84 = uStack92;
    uStack52 = uStack60;
  }
  else {
    iVar9 = iVar2 * 0xa4;
    if (*(char *)(DAT_803dd12c + iVar9 + 0xc1) < '\0') {
      local_178 = FLOAT_803df06c;
      local_174 = FLOAT_803df06c;
      local_170 = FLOAT_803df06c;
      FUN_80247794(&local_178,&local_178);
      uVar3 = FUN_8000f558();
      FUN_80247574(uVar3,&local_178,&local_178);
    }
    if ((*(byte *)(DAT_803dd12c + iVar9 + 0xc1) >> 6 & 1) == 0) {
      param_8 = param_8 + 1;
      uVar4 = (int)(uVar10 * param_8) >> 8;
      uVar5 = (int)(param_6 * param_8) >> 8;
      uVar6 = (int)(param_7 * param_8) >> 8;
      param_9 = param_9 + 1;
      local_90._7_1_ = (undefined)(uVar10 * param_9 >> 8);
      local_70._7_1_ = (undefined)(param_6 * param_9 >> 8);
      local_50._7_1_ = (undefined)(param_7 * param_9 >> 8);
    }
    else {
      iVar9 = DAT_803dd12c + iVar9;
      local_178 = *(float *)(iVar9 + 0xa8);
      local_174 = *(float *)(iVar9 + 0xac);
      local_170 = *(float *)(iVar9 + 0xb0);
      uVar10 = (uint)*(byte *)(iVar9 + 0x7c);
      param_6 = (uint)*(byte *)(iVar9 + 0x7d);
      param_7 = (uint)*(byte *)(iVar9 + 0x7e);
      uVar4 = (uint)*(byte *)(iVar9 + 0x84);
      uVar5 = (uint)*(byte *)(iVar9 + 0x85);
      uVar6 = (uint)*(byte *)(iVar9 + 0x86);
      local_90._7_1_ = *(undefined *)(iVar9 + 0x8c);
      local_70._7_1_ = *(undefined *)(iVar9 + 0x8d);
      local_50._7_1_ = *(undefined *)(iVar9 + 0x8e);
      param_10 = 0xff;
    }
  }
  iVar2 = iVar2 * 0xa4;
  *(float *)(DAT_803dd12c + iVar2 + 0x90) = local_178;
  *(float *)(DAT_803dd12c + iVar2 + 0x94) = local_174;
  *(float *)(DAT_803dd12c + iVar2 + 0x98) = local_170;
  *(char *)(DAT_803dd12c + iVar2 + 0x78) = (char)uVar10;
  *(char *)(DAT_803dd12c + iVar2 + 0x79) = (char)param_6;
  *(char *)(DAT_803dd12c + iVar2 + 0x7a) = (char)param_7;
  *(float *)(DAT_803dd12c + iVar2 + 0x9c) = -local_178;
  *(float *)(DAT_803dd12c + iVar2 + 0xa0) = -local_174;
  *(float *)(DAT_803dd12c + iVar2 + 0xa4) = -local_170;
  *(char *)(DAT_803dd12c + iVar2 + 0x80) = (char)(uVar4 * (DAT_803db634 + 1) >> 8);
  *(char *)(DAT_803dd12c + iVar2 + 0x81) = (char)(uVar5 * (DAT_803db634 + 1) >> 8);
  *(char *)(DAT_803dd12c + iVar2 + 0x82) = (char)(uVar6 * (DAT_803db634 + 1) >> 8);
  *(undefined *)(DAT_803dd12c + iVar2 + 0x88) = (undefined)local_90;
  *(undefined *)(DAT_803dd12c + iVar2 + 0x89) = (undefined)local_70;
  *(undefined *)(DAT_803dd12c + iVar2 + 0x8a) = (undefined)local_50;
  *(undefined *)(DAT_803dd12c + iVar2 + 0xc0) = param_10;
  FUN_8028611c();
  return;
}

