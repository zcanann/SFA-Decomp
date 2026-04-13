// Function: FUN_8011f088
// Entry: 8011f088
// Size: 428 bytes

/* WARNING: Removing unreachable block (ram,0x8011f20c) */
/* WARNING: Removing unreachable block (ram,0x8011f204) */
/* WARNING: Removing unreachable block (ram,0x8011f0a0) */
/* WARNING: Removing unreachable block (ram,0x8011f098) */

void FUN_8011f088(double param_1,double param_2,int param_3,int param_4,undefined param_5,
                 uint param_6,byte param_7)

{
  undefined2 uVar1;
  uint uVar2;
  uint uVar3;
  undefined2 uVar4;
  double dVar5;
  double dVar6;
  
  FUN_8011e104(param_3,param_5,(int)(short)param_4,param_7 & 4);
  uVar2 = (uint)*(ushort *)(param_3 + 10) * 4 * (param_6 & 0xffff);
  uVar3 = (uint)*(ushort *)(param_3 + 0xc) * 4 * (param_6 & 0xffff);
  dVar5 = (double)(float)((double)FLOAT_803e2b00 * param_1);
  dVar6 = (double)(float)((double)FLOAT_803e2b00 * param_2);
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_2_ = (short)(int)dVar5;
  DAT_cc008000._0_2_ = (short)(int)dVar6;
  uVar1 = (undefined2)(param_4 << 2);
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = FLOAT_803e2abc;
  DAT_cc008000 = FLOAT_803e2abc;
  uVar4 = (undefined2)
          (int)(dVar5 + (double)(float)((double)CONCAT44(0x43300000,
                                                         ((int)uVar2 >> 8) +
                                                         (uint)((int)uVar2 < 0 &&
                                                               (uVar2 & 0xff) != 0)) -
                                       DOUBLE_803e2b08));
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = (short)(int)dVar6;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = FLOAT_803e2ae8;
  DAT_cc008000 = FLOAT_803e2abc;
  DAT_cc008000._0_2_ = uVar4;
  uVar4 = (undefined2)
          (int)(dVar6 + (double)(float)((double)CONCAT44(0x43300000,
                                                         ((int)uVar3 >> 8) +
                                                         (uint)((int)uVar3 < 0 &&
                                                               (uVar3 & 0xff) != 0)) -
                                       DOUBLE_803e2b08));
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = FLOAT_803e2ae8;
  DAT_cc008000 = FLOAT_803e2ae8;
  DAT_cc008000._0_2_ = (short)(int)dVar5;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = FLOAT_803e2abc;
  DAT_cc008000 = FLOAT_803e2ae8;
  return;
}

