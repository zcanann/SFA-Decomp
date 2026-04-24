// Function: FUN_800e0e18
// Entry: 800e0e18
// Size: 1876 bytes

/* WARNING: Removing unreachable block (ram,0x800e1550) */
/* WARNING: Removing unreachable block (ram,0x800e1548) */
/* WARNING: Removing unreachable block (ram,0x800e1558) */

void FUN_800e0e18(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6)

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
  undefined4 uVar15;
  double extraout_f1;
  double dVar16;
  double dVar17;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar18;
  uint local_78 [4];
  uint local_68 [4];
  uint local_58 [12];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar18 = FUN_802860d8();
  iVar8 = (int)((ulonglong)uVar18 >> 0x20);
  iVar10 = (int)uVar18;
  uVar7 = CONCAT44(iVar10,iVar8);
  if (iVar8 == iVar10) {
    dVar17 = extraout_f1;
    dVar16 = (double)FUN_802931a0((double)((param_6[2] - param_5[2]) * (param_6[2] - param_5[2]) +
                                          (*param_6 - *param_5) * (*param_6 - *param_5) +
                                          (param_6[1] - param_5[1]) * (param_6[1] - param_5[1])));
    if (param_2 < dVar17) {
      dVar16 = -dVar16;
    }
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
          iVar8 = FUN_800221a0(0,iVar11 + -1);
          uVar12 = local_58[iVar8];
        }
        if ((int)uVar12 < 0) {
          iVar8 = 0;
        }
        else {
          iVar11 = DAT_803dd478 + -1;
          iVar9 = 0;
          while (iVar9 <= iVar11) {
            iVar14 = iVar11 + iVar9 >> 1;
            iVar8 = (&DAT_803a17e8)[iVar14];
            if (*(uint *)(iVar8 + 0x14) < uVar12) {
              iVar9 = iVar14 + 1;
            }
            else {
              if (*(uint *)(iVar8 + 0x14) <= uVar12) goto LAB_800e111c;
              iVar11 = iVar14 + -1;
            }
          }
          iVar8 = 0;
        }
LAB_800e111c:
        if (iVar8 == iVar10) {
          bVar5 = true;
          bVar6 = true;
        }
      }
    }
    pfVar13 = param_5;
    if (!bVar6) {
      pfVar13 = param_6;
      param_6 = param_5;
      uVar18 = uVar7;
    }
    iVar10 = (int)((ulonglong)uVar18 >> 0x20);
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
      iVar8 = FUN_800221a0(0,iVar9 + -1);
      uVar12 = local_68[iVar8];
    }
    if ((int)uVar12 < 0) {
      iVar9 = 0;
    }
    else {
      iVar10 = DAT_803dd478 + -1;
      iVar8 = 0;
      while (iVar8 <= iVar10) {
        iVar11 = iVar10 + iVar8 >> 1;
        iVar9 = (&DAT_803a17e8)[iVar11];
        if (*(uint *)(iVar9 + 0x14) < uVar12) {
          iVar8 = iVar11 + 1;
        }
        else {
          if (*(uint *)(iVar9 + 0x14) <= uVar12) goto LAB_800e12e0;
          iVar10 = iVar11 + -1;
        }
      }
      iVar9 = 0;
    }
LAB_800e12e0:
    fVar1 = *(float *)(iVar9 + 8) - *pfVar13;
    fVar2 = *(float *)(iVar9 + 0xc) - pfVar13[1];
    fVar3 = *(float *)(iVar9 + 0x10) - pfVar13[2];
    dVar16 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    bVar5 = false;
    while (!bVar5) {
      if (iVar9 == (int)uVar18) {
        bVar5 = true;
        fVar1 = *param_6 - *(float *)(iVar9 + 8);
        fVar2 = param_6[1] - *(float *)(iVar9 + 0xc);
        fVar3 = param_6[2] - *(float *)(iVar9 + 0x10);
        dVar17 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        dVar16 = (double)(float)(dVar16 + dVar17);
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
          iVar8 = FUN_800221a0(0,iVar10 + -1);
          uVar12 = local_78[iVar8];
        }
        if ((int)uVar12 < 0) {
          iVar14 = 0;
        }
        else {
          iVar10 = DAT_803dd478 + -1;
          iVar8 = 0;
          while (iVar8 <= iVar10) {
            iVar11 = iVar10 + iVar8 >> 1;
            iVar14 = (&DAT_803a17e8)[iVar11];
            if (*(uint *)(iVar14 + 0x14) < uVar12) {
              iVar8 = iVar11 + 1;
            }
            else {
              if (*(uint *)(iVar14 + 0x14) <= uVar12) goto LAB_800e14f4;
              iVar10 = iVar11 + -1;
            }
          }
          iVar14 = 0;
        }
LAB_800e14f4:
        fVar1 = *(float *)(iVar14 + 8) - *(float *)(iVar9 + 8);
        fVar2 = *(float *)(iVar14 + 0xc) - *(float *)(iVar9 + 0xc);
        fVar3 = *(float *)(iVar14 + 0x10) - *(float *)(iVar9 + 0x10);
        dVar17 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        dVar16 = (double)(float)(dVar16 + dVar17);
        iVar9 = iVar14;
      }
    }
    if (!bVar6) {
      dVar16 = -dVar16;
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  FUN_80286124(dVar16);
  return;
}

