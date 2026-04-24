// Function: FUN_800e1578
// Entry: 800e1578
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x800e17a0) */

void FUN_800e1578(double param_1,int param_2,float *param_3,float *param_4,float *param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f31;
  uint local_38 [6];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = 0;
  uVar8 = *(uint *)(param_2 + 0x1c);
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 1) == 0)) && (uVar8 != 0)) {
    iVar5 = 1;
    local_38[0] = uVar8;
  }
  uVar8 = *(uint *)(param_2 + 0x20);
  iVar6 = iVar5;
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 2) == 0)) && (uVar8 != 0)) {
    iVar6 = iVar5 + 1;
    local_38[iVar5] = uVar8;
  }
  uVar8 = *(uint *)(param_2 + 0x24);
  iVar5 = iVar6;
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 4) == 0)) && (uVar8 != 0)) {
    iVar5 = iVar6 + 1;
    local_38[iVar6] = uVar8;
  }
  uVar8 = *(uint *)(param_2 + 0x28);
  iVar6 = iVar5;
  if (((-1 < (int)uVar8) && ((*(byte *)(param_2 + 0x1b) & 8) == 0)) && (uVar8 != 0)) {
    iVar6 = iVar5 + 1;
    local_38[iVar5] = uVar8;
  }
  if (iVar6 == 0) {
    uVar8 = 0xffffffff;
  }
  else {
    iVar5 = FUN_800221a0(0,iVar6 + -1);
    uVar8 = local_38[iVar5];
  }
  if ((int)uVar8 < 0) {
    iVar9 = 0;
  }
  else {
    iVar6 = DAT_803dd478 + -1;
    iVar5 = 0;
    while (iVar5 <= iVar6) {
      iVar7 = iVar6 + iVar5 >> 1;
      iVar9 = (&DAT_803a17e8)[iVar7];
      if (*(uint *)(iVar9 + 0x14) < uVar8) {
        iVar5 = iVar7 + 1;
      }
      else {
        if (*(uint *)(iVar9 + 0x14) <= uVar8) goto LAB_800e1738;
        iVar6 = iVar7 + -1;
      }
    }
    iVar9 = 0;
  }
LAB_800e1738:
  if (iVar9 == 0) {
    *param_3 = *(float *)(param_2 + 8);
    *param_4 = *(float *)(param_2 + 0xc);
    *param_5 = *(float *)(param_2 + 0x10);
  }
  else {
    fVar1 = *(float *)(iVar9 + 0xc);
    fVar2 = *(float *)(param_2 + 0xc);
    fVar3 = *(float *)(iVar9 + 0x10);
    fVar4 = *(float *)(param_2 + 0x10);
    *param_3 = (float)((double)(float)((double)*(float *)(iVar9 + 8) -
                                      (double)*(float *)(param_2 + 8)) * param_1 +
                      (double)*(float *)(param_2 + 8));
    *param_4 = (float)((double)(fVar1 - fVar2) * param_1 + (double)*(float *)(param_2 + 0xc));
    *param_5 = (float)((double)(fVar3 - fVar4) * param_1 + (double)*(float *)(param_2 + 0x10));
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  return;
}

