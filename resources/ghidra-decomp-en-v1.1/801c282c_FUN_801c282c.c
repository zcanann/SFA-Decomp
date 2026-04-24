// Function: FUN_801c282c
// Entry: 801c282c
// Size: 824 bytes

/* WARNING: Removing unreachable block (ram,0x801c2b3c) */
/* WARNING: Removing unreachable block (ram,0x801c2b34) */
/* WARNING: Removing unreachable block (ram,0x801c2b2c) */
/* WARNING: Removing unreachable block (ram,0x801c2b24) */
/* WARNING: Removing unreachable block (ram,0x801c2b1c) */
/* WARNING: Removing unreachable block (ram,0x801c2b14) */
/* WARNING: Removing unreachable block (ram,0x801c2864) */
/* WARNING: Removing unreachable block (ram,0x801c285c) */
/* WARNING: Removing unreachable block (ram,0x801c2854) */
/* WARNING: Removing unreachable block (ram,0x801c284c) */
/* WARNING: Removing unreachable block (ram,0x801c2844) */
/* WARNING: Removing unreachable block (ram,0x801c283c) */

void FUN_801c282c(int param_1)

{
  float fVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  int local_78;
  int local_74;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  if ((*(byte *)(iVar6 + 0x18) & 1) != 0) {
    if (**(int **)(param_1 + 0xb8) == 0) {
      piVar3 = (int *)FUN_8002e1f4(&local_78,&local_74);
      local_78 = 0;
      iVar5 = 0;
      while ((local_78 < local_74 && (iVar5 == 0))) {
        iVar4 = *piVar3;
        if ((*(short *)(iVar4 + 0x44) == 0x36) &&
           ((uint)*(byte *)(iVar6 + 0x18) == *(byte *)(*(int *)(iVar4 + 0x4c) + 0x18) - 1)) {
          iVar5 = iVar4;
        }
        piVar3 = piVar3 + 1;
        local_78 = local_78 + 1;
      }
      if (iVar5 == 0) {
        return;
      }
      **(int **)(iVar5 + 0xb8) = param_1;
      piVar3 = *(int **)(param_1 + 0xb8);
      *piVar3 = iVar5;
      dVar9 = (double)(*(float *)(iVar5 + 0xc) - *(float *)(param_1 + 0xc));
      dVar10 = (double)(*(float *)(iVar5 + 0x10) - *(float *)(param_1 + 0x10));
      dVar12 = (double)(*(float *)(iVar5 + 0x14) - *(float *)(param_1 + 0x14));
      dVar7 = FUN_80293900((double)(float)(dVar12 * dVar12 +
                                          (double)(float)(dVar9 * dVar9 +
                                                         (double)(float)(dVar10 * dVar10))));
      iVar4 = FUN_80021884();
      sVar2 = (short)iVar4;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      *(short *)(piVar3 + 6) = sVar2;
      dVar8 = (double)FLOAT_803e5a94;
      iVar6 = FUN_801c17ec(dVar8,dVar8,dVar8,dVar9,dVar10,dVar12,dVar7,
                           (double)*(float *)(&DAT_803dcbb8 + (uint)*(byte *)(iVar6 + 0x1b) * 4));
      piVar3[0xb] = iVar6;
      piVar3[1] = *(int *)(param_1 + 0xc);
      piVar3[3] = *(int *)(param_1 + 0x14);
      piVar3[2] = *(int *)(iVar5 + 0xc);
      piVar3[4] = *(int *)(iVar5 + 0x14);
      fVar1 = (float)piVar3[1];
      if ((float)piVar3[2] < fVar1) {
        piVar3[1] = piVar3[2];
        piVar3[2] = (int)fVar1;
      }
      fVar1 = (float)piVar3[3];
      if ((float)piVar3[4] < fVar1) {
        piVar3[3] = piVar3[4];
        piVar3[4] = (int)fVar1;
      }
      fVar1 = FLOAT_803e5abc;
      piVar3[1] = (int)((float)piVar3[1] - FLOAT_803e5abc);
      piVar3[3] = (int)((float)piVar3[3] - fVar1);
      piVar3[2] = (int)((float)piVar3[2] + fVar1);
      piVar3[4] = (int)((float)piVar3[4] + fVar1);
      dVar14 = (double)*(float *)(param_1 + 0xc);
      dVar13 = (double)*(float *)(param_1 + 0x10);
      dVar11 = (double)*(float *)(param_1 + 0x14);
      dVar7 = (double)*(float *)(iVar5 + 0xc);
      dVar9 = (double)*(float *)(iVar5 + 0x10);
      dVar10 = (double)*(float *)(iVar5 + 0x14);
      dVar12 = (double)(float)((double)FLOAT_803e5ac0 + dVar13);
      dVar8 = (double)(float)(dVar12 * (double)(float)(dVar11 - dVar10) +
                             (double)(float)(dVar13 * (double)(float)(dVar10 - dVar11) +
                                            (double)(float)(dVar9 * (double)(float)(dVar11 - dVar11)
                                                           )));
      dVar10 = (double)(float)(dVar11 * (double)(float)(dVar14 - dVar7) +
                              (double)(float)(dVar11 * (double)(float)(dVar7 - dVar14) +
                                             (double)(float)(dVar10 * (double)(float)(dVar14 - 
                                                  dVar14))));
      dVar9 = (double)(float)(dVar14 * (double)(float)(dVar13 - dVar9) +
                             (double)(float)(dVar14 * (double)(float)(dVar9 - dVar12) +
                                            (double)(float)(dVar7 * (double)(float)(dVar12 - dVar13)
                                                           )));
      dVar7 = FUN_80293900((double)(float)(dVar9 * dVar9 +
                                          (double)(float)(dVar8 * dVar8 +
                                                         (double)(float)(dVar10 * dVar10))));
      if ((double)FLOAT_803e5a94 < dVar7) {
        dVar8 = (double)(float)(dVar8 / dVar7);
        dVar10 = (double)(float)(dVar10 / dVar7);
        dVar9 = (double)(float)(dVar9 / dVar7);
      }
      piVar3[7] = (int)(float)dVar8;
      piVar3[8] = (int)(float)dVar10;
      piVar3[9] = (int)(float)dVar9;
      piVar3[10] = (int)-(float)(dVar11 * dVar9 +
                                (double)(float)(dVar14 * dVar8 + (double)(float)(dVar13 * dVar10)));
    }
    FUN_801c158c();
  }
  return;
}

