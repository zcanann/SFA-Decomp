// Function: FUN_800e109c
// Entry: 800e109c
// Size: 1876 bytes

/* WARNING: Removing unreachable block (ram,0x800e17dc) */
/* WARNING: Removing unreachable block (ram,0x800e17d4) */
/* WARNING: Removing unreachable block (ram,0x800e17cc) */
/* WARNING: Removing unreachable block (ram,0x800e10bc) */
/* WARNING: Removing unreachable block (ram,0x800e10b4) */
/* WARNING: Removing unreachable block (ram,0x800e10ac) */

void FUN_800e109c(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  undefined8 uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  float *pfVar13;
  int iVar14;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  uint local_78 [4];
  uint local_68 [4];
  uint local_58 [12];
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar15 = FUN_8028683c();
  iVar8 = (int)((ulonglong)uVar15 >> 0x20);
  iVar10 = (int)uVar15;
  uVar7 = CONCAT44(iVar10,iVar8);
  if (iVar8 == iVar10) {
    FUN_80293900((double)((param_4[2] - param_3[2]) * (param_4[2] - param_3[2]) +
                         (*param_4 - *param_3) * (*param_4 - *param_3) +
                         (param_4[1] - param_3[1]) * (param_4[1] - param_3[1])));
  }
  else {
    bVar6 = false;
    bVar5 = false;
    while (!bVar5) {
      bVar4 = false;
      if ((*(int *)(iVar8 + 0x1c) == -1) || ((*(byte *)(iVar8 + 0x1b) & 1) != 0)) {
        if ((*(int *)(iVar8 + 0x20) == -1) || ((*(byte *)(iVar8 + 0x1b) & 2) != 0)) {
          if ((*(int *)(iVar8 + 0x24) == -1) || ((*(byte *)(iVar8 + 0x1b) & 4) != 0)) {
            if ((*(int *)(iVar8 + 0x28) == -1) || ((*(byte *)(iVar8 + 0x1b) & 8) != 0)) {
              bVar4 = true;
            }
            else {
              bVar4 = false;
            }
          }
          else {
            bVar4 = false;
          }
        }
        else {
          bVar4 = false;
        }
      }
      if (bVar4) {
        bVar5 = true;
        bVar6 = false;
      }
      else {
        iVar9 = 0;
        uVar12 = *(uint *)(iVar8 + 0x1c);
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 1) == 0)) && (uVar12 != 0)) {
          iVar9 = 1;
          local_58[0] = uVar12;
        }
        uVar12 = *(uint *)(iVar8 + 0x20);
        iVar11 = iVar9;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 2) == 0)) && (uVar12 != 0)) {
          iVar11 = iVar9 + 1;
          local_58[iVar9] = uVar12;
        }
        uVar12 = *(uint *)(iVar8 + 0x24);
        iVar9 = iVar11;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 4) == 0)) && (uVar12 != 0)) {
          iVar9 = iVar11 + 1;
          local_58[iVar11] = uVar12;
        }
        uVar12 = *(uint *)(iVar8 + 0x28);
        iVar11 = iVar9;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar8 + 0x1b) & 8) == 0)) && (uVar12 != 0)) {
          iVar11 = iVar9 + 1;
          local_58[iVar9] = uVar12;
        }
        if (iVar11 == 0) {
          uVar12 = 0xffffffff;
        }
        else {
          uVar12 = FUN_80022264(0,iVar11 - 1);
          uVar12 = local_58[uVar12];
        }
        if ((int)uVar12 < 0) {
          iVar8 = 0;
        }
        else {
          iVar11 = DAT_803de0f0 + -1;
          iVar9 = 0;
          while (iVar9 <= iVar11) {
            iVar14 = iVar11 + iVar9 >> 1;
            iVar8 = (&DAT_803a2448)[iVar14];
            if (*(uint *)(iVar8 + 0x14) < uVar12) {
              iVar9 = iVar14 + 1;
            }
            else {
              if (*(uint *)(iVar8 + 0x14) <= uVar12) goto LAB_800e13a0;
              iVar11 = iVar14 + -1;
            }
          }
          iVar8 = 0;
        }
LAB_800e13a0:
        if (iVar8 == iVar10) {
          bVar5 = true;
          bVar6 = true;
        }
      }
    }
    pfVar13 = param_3;
    if (!bVar6) {
      pfVar13 = param_4;
      param_4 = param_3;
      uVar15 = uVar7;
    }
    iVar10 = (int)((ulonglong)uVar15 >> 0x20);
    iVar8 = 0;
    uVar12 = *(uint *)(iVar10 + 0x1c);
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 1) == 0)) && (uVar12 != 0)) {
      iVar8 = 1;
      local_68[0] = uVar12;
    }
    uVar12 = *(uint *)(iVar10 + 0x20);
    iVar9 = iVar8;
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 2) == 0)) && (uVar12 != 0)) {
      iVar9 = iVar8 + 1;
      local_68[iVar8] = uVar12;
    }
    uVar12 = *(uint *)(iVar10 + 0x24);
    iVar8 = iVar9;
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 4) == 0)) && (uVar12 != 0)) {
      iVar8 = iVar9 + 1;
      local_68[iVar9] = uVar12;
    }
    uVar12 = *(uint *)(iVar10 + 0x28);
    iVar9 = iVar8;
    if (((-1 < (int)uVar12) && ((*(byte *)(iVar10 + 0x1b) & 8) == 0)) && (uVar12 != 0)) {
      iVar9 = iVar8 + 1;
      local_68[iVar8] = uVar12;
    }
    if (iVar9 == 0) {
      uVar12 = 0xffffffff;
    }
    else {
      uVar12 = FUN_80022264(0,iVar9 - 1);
      uVar12 = local_68[uVar12];
    }
    if ((int)uVar12 < 0) {
      iVar9 = 0;
    }
    else {
      iVar10 = DAT_803de0f0 + -1;
      iVar8 = 0;
      while (iVar8 <= iVar10) {
        iVar11 = iVar10 + iVar8 >> 1;
        iVar9 = (&DAT_803a2448)[iVar11];
        if (*(uint *)(iVar9 + 0x14) < uVar12) {
          iVar8 = iVar11 + 1;
        }
        else {
          if (*(uint *)(iVar9 + 0x14) <= uVar12) goto LAB_800e1564;
          iVar10 = iVar11 + -1;
        }
      }
      iVar9 = 0;
    }
LAB_800e1564:
    fVar1 = *(float *)(iVar9 + 8) - *pfVar13;
    fVar2 = *(float *)(iVar9 + 0xc) - pfVar13[1];
    fVar3 = *(float *)(iVar9 + 0x10) - pfVar13[2];
    FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    bVar5 = false;
    while (!bVar5) {
      if (iVar9 == (int)uVar15) {
        bVar5 = true;
        fVar1 = *param_4 - *(float *)(iVar9 + 8);
        fVar2 = param_4[1] - *(float *)(iVar9 + 0xc);
        fVar3 = param_4[2] - *(float *)(iVar9 + 0x10);
        FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
      }
      else {
        iVar8 = 0;
        uVar12 = *(uint *)(iVar9 + 0x1c);
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 1) == 0)) && (uVar12 != 0)) {
          iVar8 = 1;
          local_78[0] = uVar12;
        }
        uVar12 = *(uint *)(iVar9 + 0x20);
        iVar10 = iVar8;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 2) == 0)) && (uVar12 != 0)) {
          iVar10 = iVar8 + 1;
          local_78[iVar8] = uVar12;
        }
        uVar12 = *(uint *)(iVar9 + 0x24);
        iVar8 = iVar10;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 4) == 0)) && (uVar12 != 0)) {
          iVar8 = iVar10 + 1;
          local_78[iVar10] = uVar12;
        }
        uVar12 = *(uint *)(iVar9 + 0x28);
        iVar10 = iVar8;
        if (((-1 < (int)uVar12) && ((*(byte *)(iVar9 + 0x1b) & 8) == 0)) && (uVar12 != 0)) {
          iVar10 = iVar8 + 1;
          local_78[iVar8] = uVar12;
        }
        if (iVar10 == 0) {
          uVar12 = 0xffffffff;
        }
        else {
          uVar12 = FUN_80022264(0,iVar10 - 1);
          uVar12 = local_78[uVar12];
        }
        if ((int)uVar12 < 0) {
          iVar14 = 0;
        }
        else {
          iVar10 = DAT_803de0f0 + -1;
          iVar8 = 0;
          while (iVar8 <= iVar10) {
            iVar11 = iVar10 + iVar8 >> 1;
            iVar14 = (&DAT_803a2448)[iVar11];
            if (*(uint *)(iVar14 + 0x14) < uVar12) {
              iVar8 = iVar11 + 1;
            }
            else {
              if (*(uint *)(iVar14 + 0x14) <= uVar12) goto LAB_800e1778;
              iVar10 = iVar11 + -1;
            }
          }
          iVar14 = 0;
        }
LAB_800e1778:
        fVar1 = *(float *)(iVar14 + 8) - *(float *)(iVar9 + 8);
        fVar2 = *(float *)(iVar14 + 0xc) - *(float *)(iVar9 + 0xc);
        fVar3 = *(float *)(iVar14 + 0x10) - *(float *)(iVar9 + 0x10);
        FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        iVar9 = iVar14;
      }
    }
  }
  FUN_80286888();
  return;
}

