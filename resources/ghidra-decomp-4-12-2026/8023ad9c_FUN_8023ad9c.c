// Function: FUN_8023ad9c
// Entry: 8023ad9c
// Size: 472 bytes

/* WARNING: Removing unreachable block (ram,0x8023af50) */
/* WARNING: Removing unreachable block (ram,0x8023af48) */
/* WARNING: Removing unreachable block (ram,0x8023af40) */
/* WARNING: Removing unreachable block (ram,0x8023af38) */
/* WARNING: Removing unreachable block (ram,0x8023af30) */
/* WARNING: Removing unreachable block (ram,0x8023af28) */
/* WARNING: Removing unreachable block (ram,0x8023af20) */
/* WARNING: Removing unreachable block (ram,0x8023addc) */
/* WARNING: Removing unreachable block (ram,0x8023add4) */
/* WARNING: Removing unreachable block (ram,0x8023adcc) */
/* WARNING: Removing unreachable block (ram,0x8023adc4) */
/* WARNING: Removing unreachable block (ram,0x8023adbc) */
/* WARNING: Removing unreachable block (ram,0x8023adb4) */
/* WARNING: Removing unreachable block (ram,0x8023adac) */

undefined4 FUN_8023ad9c(double param_1,double param_2,double param_3,int *param_4)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  float local_98;
  float local_94;
  undefined4 local_88;
  uint uStack_84;
  
  uVar5 = 0;
  iVar3 = *param_4;
  fVar1 = (float)param_4[0x30] - *(float *)(iVar3 + 0xc);
  fVar2 = (float)param_4[0x31] - *(float *)(iVar3 + 0x10);
  dVar7 = (double)((float)param_4[0x32] - *(float *)(iVar3 + 0x14));
  dVar6 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  iVar3 = FUN_80021884();
  iVar4 = FUN_80021884();
  if ((12000 < (short)iVar4) && ((double)FLOAT_803dd128 < dVar7)) {
    uVar5 = 1;
  }
  dVar7 = (double)(float)(dVar6 / param_2);
  dVar6 = -param_1;
  if ((dVar6 <= dVar7) && (dVar6 = dVar7, param_1 < dVar7)) {
    dVar6 = param_1;
  }
  uStack_84 = (int)(short)iVar3 ^ 0x80000000;
  local_88 = 0x43300000;
  dVar7 = (double)FUN_802945e0();
  param_4[0x36] = (int)(float)(dVar6 * dVar7);
  dVar7 = (double)FUN_80294964();
  param_4[0x37] = (int)(float)(dVar6 * dVar7);
  FUN_8022db50(&local_98,*param_4);
  param_4[0x36] = (int)-(local_98 * FLOAT_803dd12c - (float)param_4[0x36]);
  param_4[0x37] = (int)-(local_94 * FLOAT_803dd12c - (float)param_4[0x37]);
  param_4[0x38] = (int)(float)param_3;
  return uVar5;
}

