// Function: FUN_801b2244
// Entry: 801b2244
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x801b2528) */
/* WARNING: Removing unreachable block (ram,0x801b2530) */

void FUN_801b2244(undefined8 param_1,undefined8 param_2,double param_3)

{
  char cVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  short sVar6;
  int iVar5;
  int iVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  double extraout_f1;
  double dVar15;
  double dVar16;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar17;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar7 = FUN_802860d8();
  iVar12 = *(int *)(iVar7 + 0x4c);
  dVar16 = extraout_f1;
  iVar8 = FUN_8002b9ec();
  iVar13 = *(int *)(iVar7 + 0xb8);
  if (*(short *)(iVar13 + 0xa6) < 1) {
    iVar9 = FUN_800395d8(iVar7,0);
    sVar2 = *(short *)(iVar9 + 2);
    cVar1 = *(char *)(iVar12 + 0x28);
    uVar10 = FUN_800217c0((double)(float)(dVar16 - (double)*(float *)(iVar7 + 0xc)),
                          (double)(float)(param_3 - (double)*(float *)(iVar7 + 0x14)));
    iVar7 = ((uVar10 & 0xffff) + 0x8000) - ((int)sVar2 + cVar1 * 0x100 & 0xffffU);
    if (0x8000 < iVar7) {
      iVar7 = iVar7 + -0xffff;
    }
    if (iVar7 < -0x8000) {
      iVar7 = iVar7 + 0xffff;
    }
    if ((iVar7 < 0x1200) && (-0x1200 < iVar7)) {
      *(undefined *)(iVar13 + 0xad) = 1;
    }
    if (0x800 < iVar7) {
      iVar7 = 0x800;
    }
    if (iVar7 < -0x800) {
      iVar7 = -0x800;
    }
    iVar7 = iVar7 >> 3;
    if (iVar7 != 0) {
      sVar2 = *(short *)(iVar9 + 2);
      sVar6 = sVar2;
      if (sVar2 < 0) {
        sVar6 = -sVar2;
      }
      if ((int)DAT_803dbf02 - (int)DAT_803dbf04 < (int)sVar6) {
        if (iVar7 < 0) {
          iVar11 = -1;
        }
        else if (iVar7 < 1) {
          iVar11 = 0;
        }
        else {
          iVar11 = 1;
        }
        if (sVar2 < 0) {
          iVar5 = -1;
        }
        else if (sVar2 < 1) {
          iVar5 = 0;
        }
        else {
          iVar5 = 1;
        }
        if (iVar5 == iVar11) {
          iVar7 = (iVar7 * ((int)DAT_803dbf02 - (int)sVar6)) / (int)DAT_803dbf04;
        }
      }
      *(short *)(iVar9 + 2) = *(short *)(iVar9 + 2) + (short)iVar7;
    }
    fVar3 = *(float *)(iVar13 + 0x8c) - *(float *)(iVar13 + 4);
    fVar4 = *(float *)(iVar13 + 0x94) - *(float *)(iVar13 + 0xc);
    dVar17 = (double)(fVar3 * fVar3 + fVar4 * fVar4);
    dVar15 = (double)FUN_802931a0(dVar17);
    dVar16 = (double)FLOAT_803e48c8;
    fVar3 = (float)(dVar16 + (double)*(float *)(iVar13 + 8)) - *(float *)(iVar13 + 0x90);
    if (dVar16 < dVar17) {
      dVar16 = dVar17;
    }
    iVar7 = (uint)*(byte *)(iVar12 + 0x2b) * 2;
    if (((dVar16 < (double)(float)((double)CONCAT44(0x43300000,iVar7 * iVar7 ^ 0x80000000) -
                                  DOUBLE_803e48c0)) || (fVar3 < FLOAT_803dbf14)) ||
       ((*(ushort *)(iVar8 + 0xb0) & 0x1000) != 0)) {
      *(undefined *)(iVar13 + 0xad) = 0;
    }
    iVar7 = (uint)*(byte *)(iVar12 + 0x2b) * 2;
    uVar10 = iVar7 * iVar7 ^ 0x80000000;
    if (dVar16 <= (double)(float)((double)CONCAT44(0x43300000,uVar10) - DOUBLE_803e48c0)) {
      dVar16 = (double)(float)((double)CONCAT44(0x43300000,uVar10) - DOUBLE_803e48c0);
    }
    fVar3 = FLOAT_803e48cc * fVar3 - (float)((double)FLOAT_803e48d0 * dVar15);
    fVar4 = FLOAT_803e48d4;
    if (fVar3 < FLOAT_803e48d4) {
      fVar4 = fVar3;
    }
    dVar15 = (double)((float)((double)(FLOAT_803e48a4 * -FLOAT_803dbef0) * dVar16) / fVar4);
    dVar16 = (double)FLOAT_803e48b8;
    if (dVar16 < dVar15) {
      dVar16 = dVar15;
    }
    dVar16 = (double)FUN_802931a0(dVar16);
    *(float *)(iVar13 + 0x98) =
         (float)((double)*(float *)(iVar13 + 0x98) +
                (double)((float)(dVar16 - (double)*(float *)(iVar13 + 0x98)) / FLOAT_803e48d8));
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  FUN_80286124();
  return;
}

