// Function: FUN_800e17fc
// Entry: 800e17fc
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x800e1a24) */
/* WARNING: Removing unreachable block (ram,0x800e180c) */

void FUN_800e17fc(double param_1,int param_2,float *param_3,float *param_4,float *param_5)

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
  uint local_38 [6];
  
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
    uVar8 = FUN_80022264(0,iVar6 - 1);
    uVar8 = local_38[uVar8];
  }
  if ((int)uVar8 < 0) {
    iVar9 = 0;
  }
  else {
    iVar6 = DAT_803de0f0 + -1;
    iVar5 = 0;
    while (iVar5 <= iVar6) {
      iVar7 = iVar6 + iVar5 >> 1;
      iVar9 = (&DAT_803a2448)[iVar7];
      if (*(uint *)(iVar9 + 0x14) < uVar8) {
        iVar5 = iVar7 + 1;
      }
      else {
        if (*(uint *)(iVar9 + 0x14) <= uVar8) goto LAB_800e19bc;
        iVar6 = iVar7 + -1;
      }
    }
    iVar9 = 0;
  }
LAB_800e19bc:
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
  return;
}

