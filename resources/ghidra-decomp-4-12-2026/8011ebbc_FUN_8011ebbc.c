// Function: FUN_8011ebbc
// Entry: 8011ebbc
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x8011ee00) */
/* WARNING: Removing unreachable block (ram,0x8011edf8) */
/* WARNING: Removing unreachable block (ram,0x8011edf0) */
/* WARNING: Removing unreachable block (ram,0x8011ede8) */
/* WARNING: Removing unreachable block (ram,0x8011ede0) */
/* WARNING: Removing unreachable block (ram,0x8011edd8) */
/* WARNING: Removing unreachable block (ram,0x8011ebf4) */
/* WARNING: Removing unreachable block (ram,0x8011ebec) */
/* WARNING: Removing unreachable block (ram,0x8011ebe4) */
/* WARNING: Removing unreachable block (ram,0x8011ebdc) */
/* WARNING: Removing unreachable block (ram,0x8011ebd4) */
/* WARNING: Removing unreachable block (ram,0x8011ebcc) */

void FUN_8011ebbc(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined param_5,int param_6,int param_7,int param_8,int param_9)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  double extraout_f1;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar10 >> 0x20);
  dVar4 = extraout_f1;
  FUN_8011e104(iVar3,param_5,(int)(short)uVar10,'\0');
  dVar5 = (double)(float)((double)FLOAT_803e2b00 * dVar4);
  dVar6 = (double)(float)((double)FLOAT_803e2b00 * param_2);
  dVar8 = (double)((float)((double)CONCAT44(0x43300000,param_8) - DOUBLE_803e2b08) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 10)) -
                         DOUBLE_803e2b08));
  dVar7 = (double)((float)((double)CONCAT44(0x43300000,param_9) - DOUBLE_803e2b08) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0xc)) -
                         DOUBLE_803e2b08));
  dVar9 = (double)((float)((double)CONCAT44(0x43300000,param_6 + param_8) - DOUBLE_803e2b08) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 10)) -
                         DOUBLE_803e2b08));
  dVar4 = (double)((float)((double)CONCAT44(0x43300000,param_7 + param_9) - DOUBLE_803e2b08) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0xc)) -
                         DOUBLE_803e2b08));
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_2_ = (short)(int)dVar5;
  DAT_cc008000._0_2_ = (short)(int)dVar6;
  uVar1 = (undefined2)((int)uVar10 << 2);
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar8;
  DAT_cc008000 = (float)dVar7;
  uVar2 = (undefined2)
          (int)(dVar5 + (double)(float)((double)CONCAT44(0x43300000,param_6 << 2) - DOUBLE_803e2b08)
               );
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = (short)(int)dVar6;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar9;
  DAT_cc008000 = (float)dVar7;
  DAT_cc008000._0_2_ = uVar2;
  uVar2 = (undefined2)
          (int)(dVar6 + (double)(float)((double)CONCAT44(0x43300000,param_7 << 2) - DOUBLE_803e2b08)
               );
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar9;
  DAT_cc008000 = (float)dVar4;
  DAT_cc008000._0_2_ = (short)(int)dVar5;
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000 = (float)dVar8;
  DAT_cc008000 = (float)dVar4;
  FUN_80286888();
  return;
}

