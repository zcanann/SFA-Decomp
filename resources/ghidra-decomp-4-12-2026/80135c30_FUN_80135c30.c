// Function: FUN_80135c30
// Entry: 80135c30
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x80135df8) */
/* WARNING: Removing unreachable block (ram,0x80135df0) */
/* WARNING: Removing unreachable block (ram,0x80135de8) */
/* WARNING: Removing unreachable block (ram,0x80135de0) */
/* WARNING: Removing unreachable block (ram,0x80135c58) */
/* WARNING: Removing unreachable block (ram,0x80135c50) */
/* WARNING: Removing unreachable block (ram,0x80135c48) */
/* WARNING: Removing unreachable block (ram,0x80135c40) */

void FUN_80135c30(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,short param_7,undefined2 param_8)

{
  short sVar3;
  int iVar1;
  int iVar2;
  undefined2 extraout_r4;
  double extraout_f1;
  double dVar4;
  
  sVar3 = FUN_80286840();
  dVar4 = extraout_f1;
  FUN_8025d80c((float *)&DAT_803aac44,0);
  FUN_8025d888(0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  iVar1 = FUN_80286718((double)DAT_803aac60);
  iVar2 = FUN_80286718((double)DAT_803aac50);
  FUN_8025da88(iVar2 + 0x39,iVar1 + 0x4e,0x104,0x16);
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_2_ = (sVar3 - (short)(DAT_803de63c << 2)) + 0x208;
  DAT_cc008000._0_2_ = extraout_r4;
  DAT_cc008000._0_2_ = 0xffe0;
  DAT_cc008000 = (float)dVar4;
  DAT_cc008000 = (float)param_2;
  DAT_cc008000._0_2_ = (param_7 - (short)(DAT_803de63c << 2)) + 0x208;
  DAT_cc008000._0_2_ = extraout_r4;
  DAT_cc008000._0_2_ = 0xffe0;
  DAT_cc008000 = (float)param_3;
  DAT_cc008000 = (float)param_2;
  DAT_cc008000._0_2_ = (param_7 - (short)(DAT_803de63c << 2)) + 0x208;
  DAT_cc008000._0_2_ = param_8;
  DAT_cc008000._0_2_ = 0xffe0;
  DAT_cc008000 = (float)param_3;
  DAT_cc008000 = (float)param_4;
  DAT_cc008000._0_2_ = (sVar3 - (short)(DAT_803de63c << 2)) + 0x208;
  DAT_cc008000._0_2_ = param_8;
  DAT_cc008000._0_2_ = 0xffe0;
  DAT_cc008000 = (float)dVar4;
  DAT_cc008000 = (float)param_4;
  FUN_8025da88(0,0,0x280,0x1e0);
  FUN_8000fb20();
  FUN_8028688c();
  return;
}

