// Function: FUN_8025ca38
// Entry: 8025ca38
// Size: 432 bytes

void FUN_8025ca38(double param_1,double param_2,double param_3,double param_4,uint param_5,
                 uint3 *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  double dVar6;
  
  fVar2 = FLOAT_803e8398;
  fVar3 = FLOAT_803e8398;
  fVar1 = FLOAT_803e839c;
  if ((param_4 != param_3) && (param_2 != param_1)) {
    fVar2 = (float)(param_4 * param_3) /
            (float)((double)(float)(param_4 - param_3) * (double)(float)(param_2 - param_1));
    fVar3 = (float)(param_1 / (double)(float)(param_2 - param_1));
    fVar1 = (float)(param_4 / (double)(float)(param_4 - param_3));
  }
  iVar4 = 0;
  while (dVar6 = (double)fVar1, DOUBLE_803e83a0 < dVar6) {
    iVar4 = iVar4 + 1;
    fVar1 = (float)(dVar6 * (double)FLOAT_803e839c);
  }
  for (; ((double)FLOAT_803e8398 < dVar6 && (dVar6 < DOUBLE_803e83b0));
      dVar6 = (double)(float)(dVar6 * (double)FLOAT_803e83a8)) {
    iVar4 = iVar4 + -1;
  }
  fVar2 = fVar2 / (float)((double)CONCAT44(0x43300000,1 << iVar4 + 1U ^ 0x80000000) -
                         DOUBLE_803e83c0);
  uVar5 = FUN_80286718((double)(float)((double)FLOAT_803e83b8 * dVar6));
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (uint)fVar2 >> 0xc & 0x7ff | (uint)fVar2 >> 0xc & 0x7f800 |
                 (uint)fVar2 >> 0xc & 0x80000 | 0xee000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar5 & 0xffffff | 0xef000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = iVar4 + 1U & 0xffffff | 0xf0000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (uint)fVar3 >> 0xc & 0x7ff | (uint)fVar3 >> 0xc & 0x7f800 |
                 (uint)fVar3 >> 0xc & 0x80000 | (param_5 & 7) << 0x15 | 0xf1000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *param_6 | 0xf2000000;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

