// Function: FUN_801990e4
// Entry: 801990e4
// Size: 640 bytes

/* WARNING: Removing unreachable block (ram,0x80199344) */
/* WARNING: Removing unreachable block (ram,0x8019933c) */
/* WARNING: Removing unreachable block (ram,0x80199334) */
/* WARNING: Removing unreachable block (ram,0x8019932c) */
/* WARNING: Removing unreachable block (ram,0x80199324) */
/* WARNING: Removing unreachable block (ram,0x8019931c) */
/* WARNING: Removing unreachable block (ram,0x8019911c) */
/* WARNING: Removing unreachable block (ram,0x80199114) */
/* WARNING: Removing unreachable block (ram,0x8019910c) */
/* WARNING: Removing unreachable block (ram,0x80199104) */
/* WARNING: Removing unreachable block (ram,0x801990fc) */
/* WARNING: Removing unreachable block (ram,0x801990f4) */

undefined4 FUN_801990e4(int param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  dVar12 = (double)*param_2;
  dVar11 = (double)param_2[1];
  dVar10 = (double)param_2[2];
  dVar6 = (double)FUN_802945e0();
  dVar7 = (double)FUN_80294964();
  dVar8 = (double)FUN_802945e0();
  dVar9 = (double)FUN_80294964();
  dVar12 = (double)(float)(dVar12 - (double)*(float *)(param_1 + 0x18));
  dVar11 = (double)(float)(dVar11 - (double)*(float *)(param_1 + 0x1c));
  dVar10 = (double)(float)(dVar10 - (double)*(float *)(param_1 + 0x20));
  fVar2 = (float)(dVar12 * dVar7 - (double)(float)(dVar10 * dVar6));
  dVar6 = (double)(float)(dVar12 * dVar6 + (double)(float)(dVar10 * dVar7));
  fVar3 = (float)(dVar11 * dVar9 - (double)(float)(dVar6 * dVar8));
  fVar1 = (float)(dVar11 * dVar8 + (double)(float)(dVar6 * dVar9));
  if (fVar2 < FLOAT_803e4d70) {
    fVar2 = -fVar2;
  }
  if (fVar3 < FLOAT_803e4d70) {
    fVar3 = -fVar3;
  }
  if (fVar1 < FLOAT_803e4d70) {
    fVar1 = -fVar1;
  }
  if ((((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3a) << 1 ^ 0x80000000) -
               DOUBLE_803e4d68) < fVar2) ||
      ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3b) << 1 ^ 0x80000000) -
              DOUBLE_803e4d68) < fVar3)) ||
     ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3c) << 1 ^ 0x80000000) -
             DOUBLE_803e4d68) < fVar1)) {
    uVar4 = 0;
  }
  else {
    uVar4 = 1;
  }
  return uVar4;
}

