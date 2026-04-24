// Function: FUN_8025c2d4
// Entry: 8025c2d4
// Size: 432 bytes

void FUN_8025c2d4(double param_1,double param_2,double param_3,double param_4,uint param_5,
                 uint3 *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  double dVar6;
  
  fVar1 = FLOAT_803e7704;
  fVar2 = FLOAT_803e7700;
  fVar3 = FLOAT_803e7700;
  if ((param_4 != param_3) && (param_2 != param_1)) {
    fVar1 = (float)(param_4 / (double)(float)(param_4 - param_3));
    fVar2 = (float)(param_4 * param_3) /
            (float)((double)(float)(param_4 - param_3) * (double)(float)(param_2 - param_1));
    fVar3 = (float)(param_1 / (double)(float)(param_2 - param_1));
  }
  iVar4 = 0;
  while (dVar6 = (double)fVar1, DOUBLE_803e7708 < dVar6) {
    iVar4 = iVar4 + 1;
    fVar1 = (float)(dVar6 * (double)FLOAT_803e7704);
  }
  for (; ((double)FLOAT_803e7700 < dVar6 && (dVar6 < DOUBLE_803e7718));
      dVar6 = (double)(float)(dVar6 * (double)FLOAT_803e7710)) {
    iVar4 = iVar4 + -1;
  }
  fVar2 = fVar2 / (float)((double)CONCAT44(0x43300000,1 << iVar4 + 1U ^ 0x80000000) -
                         DOUBLE_803e7728);
  uVar5 = FUN_80285fb4((double)(float)((double)FLOAT_803e7720 * dVar6));
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (uint)fVar2 >> 0xc & 0x7ff | (uint)fVar2 >> 0xc & 0x7f800 |
                   (uint)fVar2 >> 0xc & 0x80000 | 0xee000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,uVar5 & 0xffffff | 0xef000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,iVar4 + 1U & 0xffffff | 0xf0000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (uint)fVar3 >> 0xc & 0x7ff | (uint)fVar3 >> 0xc & 0x7f800 |
                   (uint)fVar3 >> 0xc & 0x80000 | (param_5 & 7) << 0x15 | 0xf1000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*param_6 | 0xf2000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

