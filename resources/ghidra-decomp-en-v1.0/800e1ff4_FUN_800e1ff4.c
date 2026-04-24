// Function: FUN_800e1ff4
// Entry: 800e1ff4
// Size: 536 bytes

/* WARNING: Removing unreachable block (ram,0x800e21ec) */
/* WARNING: Removing unreachable block (ram,0x800e21e4) */
/* WARNING: Removing unreachable block (ram,0x800e21f4) */

void FUN_800e1ff4(undefined8 param_1,double param_2,double param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  undefined4 uVar14;
  double extraout_f1;
  double dVar15;
  undefined8 in_f29;
  double dVar16;
  undefined8 in_f30;
  undefined8 in_f31;
  longlong lVar17;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  lVar17 = FUN_802860d8();
  uVar4 = (uint)((ulonglong)lVar17 >> 0x20);
  pfVar5 = (float *)lVar17;
  if (lVar17 < 0) {
    iVar9 = 0;
  }
  else {
    iVar7 = DAT_803dd478 + -1;
    iVar11 = 0;
    while (iVar11 <= iVar7) {
      iVar8 = iVar7 + iVar11 >> 1;
      iVar9 = (&DAT_803a17e8)[iVar8];
      if (*(uint *)(iVar9 + 0x14) < uVar4) {
        iVar11 = iVar8 + 1;
      }
      else {
        if (*(uint *)(iVar9 + 0x14) <= uVar4) goto LAB_800e20a0;
        iVar7 = iVar8 + -1;
      }
    }
    iVar9 = 0;
  }
LAB_800e20a0:
  uVar12 = 0;
  *pfVar5 = FLOAT_803e065c;
  uVar10 = uVar4;
  dVar16 = extraout_f1;
  do {
    uVar13 = 0xffffffff;
    iVar7 = 0;
    iVar11 = iVar9;
    while ((iVar7 < 4 && (uVar13 == 0xffffffff))) {
      if (((int)*(char *)(iVar9 + 0x1b) & 1 << iVar7) == 0) {
        uVar13 = *(uint *)(iVar11 + 0x1c);
      }
      iVar11 = iVar11 + 4;
      iVar7 = iVar7 + 1;
    }
    iVar11 = iVar9;
    if (uVar13 != 0xffffffff) {
      if ((int)uVar13 < 0) {
        iVar11 = 0;
      }
      else {
        iVar8 = DAT_803dd478 + -1;
        iVar7 = 0;
        while (iVar7 <= iVar8) {
          iVar6 = iVar8 + iVar7 >> 1;
          iVar11 = (&DAT_803a17e8)[iVar6];
          if (*(uint *)(iVar11 + 0x14) < uVar13) {
            iVar7 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar11 + 0x14) <= uVar13) goto LAB_800e2168;
            iVar8 = iVar6 + -1;
          }
        }
        iVar11 = 0;
      }
LAB_800e2168:
      iVar7 = FUN_800e1f3c(dVar16,param_2,param_3,(double)FLOAT_803e0660,iVar9,iVar11);
      uVar10 = uVar13;
      if (iVar7 != 0) {
        fVar1 = (float)((double)*(float *)(iVar9 + 8) - dVar16);
        fVar2 = (float)((double)*(float *)(iVar9 + 0xc) - param_2);
        fVar3 = (float)((double)*(float *)(iVar9 + 0x10) - param_3);
        dVar15 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar15 < (double)*pfVar5) {
          *pfVar5 = (float)dVar15;
        }
        uVar12 = uVar12 + 1;
      }
    }
    if ((uVar10 == uVar4) || (iVar9 = iVar11, uVar13 == 0xffffffff)) {
      __psq_l0(auStack8,uVar14);
      __psq_l1(auStack8,uVar14);
      __psq_l0(auStack24,uVar14);
      __psq_l1(auStack24,uVar14);
      __psq_l0(auStack40,uVar14);
      __psq_l1(auStack40,uVar14);
      FUN_80286124(uVar12 & 1);
      return;
    }
  } while( true );
}

