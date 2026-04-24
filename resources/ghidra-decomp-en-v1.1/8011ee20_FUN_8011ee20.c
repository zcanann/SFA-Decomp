// Function: FUN_8011ee20
// Entry: 8011ee20
// Size: 616 bytes

/* WARNING: Removing unreachable block (ram,0x8011f068) */
/* WARNING: Removing unreachable block (ram,0x8011f060) */
/* WARNING: Removing unreachable block (ram,0x8011f058) */
/* WARNING: Removing unreachable block (ram,0x8011f050) */
/* WARNING: Removing unreachable block (ram,0x8011f048) */
/* WARNING: Removing unreachable block (ram,0x8011f040) */
/* WARNING: Removing unreachable block (ram,0x8011ee58) */
/* WARNING: Removing unreachable block (ram,0x8011ee50) */
/* WARNING: Removing unreachable block (ram,0x8011ee48) */
/* WARNING: Removing unreachable block (ram,0x8011ee40) */
/* WARNING: Removing unreachable block (ram,0x8011ee38) */
/* WARNING: Removing unreachable block (ram,0x8011ee30) */

void FUN_8011ee20(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined param_5,uint param_6,int param_7,int param_8,uint param_9)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  double dVar4;
  double extraout_f1;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 uVar11;
  undefined8 local_d8;
  undefined8 local_c8;
  undefined8 local_c0;
  
  uVar11 = FUN_80286838();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  dVar4 = extraout_f1;
  FUN_8011e104(iVar3,param_5,(int)(short)uVar11,(byte)param_9 & 4);
  dVar9 = (double)(float)((double)FLOAT_803e2b00 * dVar4);
  dVar10 = (double)(float)((double)FLOAT_803e2b00 * param_2);
  local_d8 = (double)CONCAT44(0x43300000,param_7);
  dVar5 = (double)((float)(local_d8 - DOUBLE_803e2b08) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 10)) -
                         DOUBLE_803e2b08));
  local_c8 = (double)CONCAT44(0x43300000,param_8);
  local_c0 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0xc));
  dVar4 = (double)((float)(local_c8 - DOUBLE_803e2b08) / (float)(local_c0 - DOUBLE_803e2b08));
  if ((param_9 & 1) == 0) {
    dVar8 = (double)FLOAT_803e2abc;
    dVar7 = dVar5;
  }
  else {
    dVar7 = (double)FLOAT_803e2abc;
    dVar8 = dVar5;
  }
  if ((param_9 & 2) == 0) {
    dVar6 = (double)FLOAT_803e2abc;
    dVar5 = dVar4;
  }
  else {
    dVar5 = (double)FLOAT_803e2abc;
    dVar6 = dVar4;
  }
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_2_ = (short)(int)dVar9;
  DAT_cc008000._0_2_ = (short)(int)dVar10;
  uVar1 = (undefined2)((int)uVar11 << 2);
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar8;
  DAT_cc008000 = (float)dVar6;
  uVar2 = (undefined2)
          (int)(dVar9 + (double)(float)((double)CONCAT44(0x43300000,
                                                         param_7 * 4 * (param_6 & 0xffff) >> 8) -
                                       DOUBLE_803e2b08));
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = (short)(int)dVar10;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar7;
  DAT_cc008000 = (float)dVar6;
  DAT_cc008000._0_2_ = uVar2;
  uVar2 = (undefined2)
          (int)(dVar10 + (double)(float)((double)CONCAT44(0x43300000,
                                                          param_8 * 4 * (param_6 & 0xffff) >> 8) -
                                        DOUBLE_803e2b08));
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar7;
  DAT_cc008000 = (float)dVar5;
  DAT_cc008000._0_2_ = (short)(int)dVar9;
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar8;
  DAT_cc008000 = (float)dVar5;
  FUN_80286884();
  return;
}

