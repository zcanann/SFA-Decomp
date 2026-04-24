// Function: FUN_8011e974
// Entry: 8011e974
// Size: 584 bytes

/* WARNING: Removing unreachable block (ram,0x8011eb94) */
/* WARNING: Removing unreachable block (ram,0x8011eb8c) */
/* WARNING: Removing unreachable block (ram,0x8011eb84) */
/* WARNING: Removing unreachable block (ram,0x8011eb7c) */
/* WARNING: Removing unreachable block (ram,0x8011e99c) */
/* WARNING: Removing unreachable block (ram,0x8011e994) */
/* WARNING: Removing unreachable block (ram,0x8011e98c) */
/* WARNING: Removing unreachable block (ram,0x8011e984) */

void FUN_8011e974(double param_1,double param_2,double param_3,double param_4,int param_5,
                 int param_6,int param_7,int param_8)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  
  FUN_8025d80c((float *)&DAT_803a9490,0);
  FUN_8025d848((float *)&DAT_803a9490,0);
  FUN_8025d888(0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  fVar1 = (float)((double)CONCAT44(0x43300000,param_5 - 0x500U ^ 0x80000000) - DOUBLE_803e2af8) *
          FLOAT_803dc6f4;
  fVar2 = (float)((double)CONCAT44(0x43300000,param_6 - 0x3c0U ^ 0x80000000) - DOUBLE_803e2af8) *
          FLOAT_803dc6f4;
  fVar3 = (float)((double)CONCAT44(0x43300000,param_7 - 0x500U ^ 0x80000000) - DOUBLE_803e2af8) *
          FLOAT_803dc6f4;
  fVar4 = (float)((double)CONCAT44(0x43300000,param_8 - 0x3c0U ^ 0x80000000) - DOUBLE_803e2af8) *
          FLOAT_803dc6f4;
  FUN_80259000(0x80,1,4);
  sVar5 = (short)(int)fVar1 + 0x500;
  DAT_cc008000._0_2_ = sVar5;
  sVar6 = (short)(int)fVar2 + 0x3c0;
  DAT_cc008000._0_2_ = sVar6;
  DAT_cc008000._0_2_ = (short)((int)DAT_803dc6f2 << 2);
  DAT_cc008000 = (float)param_1;
  DAT_cc008000 = (float)param_2;
  sVar7 = (short)(int)fVar3 + 0x500;
  DAT_cc008000._0_2_ = sVar7;
  DAT_cc008000._0_2_ = sVar6;
  DAT_cc008000._0_2_ = (short)((int)DAT_803dc6f2 << 2);
  DAT_cc008000 = (float)param_3;
  DAT_cc008000 = (float)param_2;
  DAT_cc008000._0_2_ = sVar7;
  sVar6 = (short)(int)fVar4 + 0x3c0;
  DAT_cc008000._0_2_ = sVar6;
  DAT_cc008000._0_2_ = (short)((int)DAT_803dc6f2 << 2);
  DAT_cc008000 = (float)param_3;
  DAT_cc008000 = (float)param_4;
  DAT_cc008000._0_2_ = sVar5;
  DAT_cc008000._0_2_ = sVar6;
  DAT_cc008000._0_2_ = (short)((int)DAT_803dc6f2 << 2);
  DAT_cc008000 = (float)param_1;
  DAT_cc008000 = (float)param_4;
  return;
}

