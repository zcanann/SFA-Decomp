// Function: FUN_800e61a0
// Entry: 800e61a0
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x800e63f0) */
/* WARNING: Removing unreachable block (ram,0x800e63e8) */
/* WARNING: Removing unreachable block (ram,0x800e63e0) */
/* WARNING: Removing unreachable block (ram,0x800e63d8) */
/* WARNING: Removing unreachable block (ram,0x800e61c8) */
/* WARNING: Removing unreachable block (ram,0x800e61c0) */
/* WARNING: Removing unreachable block (ram,0x800e61b8) */
/* WARNING: Removing unreachable block (ram,0x800e61b0) */

void FUN_800e61a0(int param_1,int param_2)

{
  float fVar1;
  bool bVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  int local_58 [4];
  
  dVar9 = (double)FLOAT_803e1324;
  dVar6 = (double)FLOAT_803e1328;
  dVar7 = (double)FLOAT_803e12e8;
  dVar8 = (double)FLOAT_803e130c;
  pfVar3 = (float *)FUN_800e6dbc((double)*(float *)(param_2 + 8),(double)*(float *)(param_2 + 0x10),
                                 param_1,local_58,0);
  *(float *)(param_2 + 0x200) = (float)dVar9;
  *(float *)(param_2 + 0x1f0) = (float)dVar9;
  *(float *)(param_2 + 0x1d0) = (float)dVar6;
  *(float *)(param_2 + 0x1e0) = (float)dVar7;
  *(float *)(param_2 + 0x1c0) = (float)dVar7;
  *(float *)(param_2 + 0x210) = (float)dVar7;
  *(float *)(param_2 + 0x220) = (float)dVar8;
  *(float *)(param_2 + 0x230) = (float)dVar7;
  bVar2 = false;
  pfVar4 = pfVar3;
  for (iVar5 = 0; iVar5 < local_58[0]; iVar5 = iVar5 + 1) {
    if (*(char *)(pfVar4 + 5) != '\x0e') {
      if (((bVar2) || (FLOAT_803e132c + *(float *)(param_2 + 0xc) <= *pfVar4)) ||
         (pfVar4[2] <= FLOAT_803e12f8)) {
        if ((FLOAT_803e132c + *(float *)(param_2 + 0xc) <= *pfVar4) && (pfVar4[2] < FLOAT_803e12e8))
        {
          *(float *)(param_2 + 0x1d0) = *pfVar4;
        }
      }
      else {
        *(float *)(param_2 + 0x1f0) = *pfVar4;
        *(float *)(param_2 + 0x1c0) = *(float *)(param_2 + 0xc) - *pfVar4;
        if (*(char *)(param_2 + 0xb8) == -1) {
          *(undefined *)(param_2 + 0xb8) = *(undefined *)(pfVar4 + 5);
        }
        bVar2 = true;
      }
    }
    pfVar4 = pfVar4 + 6;
  }
  if (!bVar2) {
    *(float *)(param_2 + 0x1c0) = FLOAT_803e1330;
  }
  if ((*(byte *)(param_2 + 0x260) & 0x10) != 0) {
    *(float *)(param_2 + 0x1c0) = FLOAT_803e12e8;
  }
  for (iVar5 = 0; iVar5 < local_58[0]; iVar5 = iVar5 + 1) {
    if (((*(char *)(pfVar3 + 5) == '\x0e') && (FLOAT_803e1334 < pfVar3[2])) &&
       ((fVar1 = *pfVar3, fVar1 < *(float *)(param_2 + 0x1d0) &&
        (*(float *)(param_2 + 0x1f0) < fVar1)))) {
      *(float *)(param_2 + 0x200) = fVar1;
      *(float *)(param_2 + 0x210) = pfVar3[1];
      *(float *)(param_2 + 0x220) = pfVar3[2];
      *(float *)(param_2 + 0x230) = pfVar3[3];
    }
    pfVar3 = pfVar3 + 6;
  }
  if (dVar9 != (double)*(float *)(param_2 + 0x200)) {
    *(float *)(param_2 + 0x1e0) =
         (float)((double)*(float *)(param_2 + 0x200) - (double)*(float *)(param_2 + 0xc));
  }
  *(undefined4 *)(param_2 + 0x1bc) = *(undefined4 *)(param_2 + 0x200);
  *(undefined4 *)(param_2 + 0x1b8) = *(undefined4 *)(param_2 + 0x1f0);
  *(undefined4 *)(param_2 + 0x1b0) = *(undefined4 *)(param_2 + 0x1d0);
  *(undefined4 *)(param_2 + 0x1b4) = *(undefined4 *)(param_2 + 0x1e0);
  *(undefined4 *)(param_2 + 0x1ac) = *(undefined4 *)(param_2 + 0x1c0);
  return;
}

