// Function: FUN_801228fc
// Entry: 801228fc
// Size: 2064 bytes

/* WARNING: Removing unreachable block (ram,0x801230e4) */
/* WARNING: Removing unreachable block (ram,0x801230ec) */

void FUN_801228fc(void)

{
  float fVar1;
  uint uVar2;
  float fVar3;
  char cVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  float *pfVar8;
  int *piVar9;
  byte bVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  int local_78 [4];
  int local_68;
  undefined4 local_60;
  undefined4 local_5c;
  int local_58;
  uint local_54;
  int local_50;
  int local_4c;
  int local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_802860d8();
  iVar5 = FUN_8002b9ec();
  FUN_8002b9ac();
  pbVar6 = (byte *)(**(code **)(*DAT_803dcaac + 0x94))();
  local_78[0] = FUN_80296ae8(iVar5);
  local_5c = FUN_80296ad4(iVar5);
  local_78[1] = FUN_8001ffb4(0xc1);
  iVar7 = FUN_80296a14(iVar5);
  if (DAT_803a9328 - iVar7 < 0) {
    local_78[2] = -1;
  }
  else {
    iVar7 = FUN_80296a14(iVar5);
    if (DAT_803a9328 - iVar7 < 1) {
      local_78[2] = 0;
    }
    else {
      local_78[2] = 1;
    }
  }
  local_78[2] = DAT_803a9328 - local_78[2];
  iVar7 = FUN_80296a8c(iVar5);
  if (DAT_803a9340 - iVar7 < 0) {
    cVar4 = -1;
  }
  else {
    iVar7 = FUN_80296a8c(iVar5);
    if (DAT_803a9340 - iVar7 < 1) {
      cVar4 = '\0';
    }
    else {
      cVar4 = '\x01';
    }
  }
  local_58 = DAT_803a9340 + -cVar4;
  if ((((-cVar4 != 0) && (FLOAT_803dd83c != FLOAT_803e1e3c)) &&
      (iVar7 = FUN_80295bc8(iVar5), iVar7 != 0)) && (iVar7 = FUN_8001ffb4(0xeb1), iVar7 != 0)) {
    FUN_8000da58(0,0x3f0);
  }
  DAT_803a936c = local_78[2];
  DAT_803a9384 = local_58;
  local_68 = FUN_8001ffb4(0x66c);
  local_50 = FUN_8001ffb4(0x13d);
  if (local_50 != DAT_803a9348) {
    FUN_800200e8(0x967,local_50 == 0);
  }
  local_4c = FUN_8001ffb4(0x86a);
  local_48 = FUN_8001ffb4(0x3f5);
  local_78[3] = FUN_8029689c(iVar5);
  local_54 = (uint)*pbVar6;
  if ((((DAT_803dd792 & 1) == 0) &&
      (((dVar13 = (double)(**(code **)(*DAT_803dca4c + 0x18))(), (double)FLOAT_803e1e3c != dVar13 ||
        (iVar7 = (**(code **)(*DAT_803dca50 + 0x10))(), iVar7 == 0x44)) ||
       (((*(ushort *)(iVar5 + 0xb0) & 0x1000) != 0 ||
        ((iVar7 = FUN_8002073c(), iVar7 != 0 || (DAT_803dd75b != '\0')))))))) ||
     (DAT_803dd780 != '\0')) {
    FLOAT_803dd83c = -(FLOAT_803e1fa0 * FLOAT_803db414 - FLOAT_803dd83c);
    if (FLOAT_803dd83c < FLOAT_803e1e3c) {
      FLOAT_803dd83c = FLOAT_803e1e3c;
    }
  }
  else {
    FLOAT_803dd83c = FLOAT_803e1fa0 * FLOAT_803db414 + FLOAT_803dd83c;
    if (FLOAT_803e1ec0 < FLOAT_803dd83c) {
      FLOAT_803dd83c = FLOAT_803e1ec0;
    }
  }
  if ((DAT_803dd793 == '\0') && (iVar7 = FUN_8001ffb4(0xa7b), iVar7 != 0)) {
    DAT_803dd793 = '\x01';
  }
  for (bVar10 = 0; fVar1 = FLOAT_803e1fbc, bVar10 < 0xd; bVar10 = bVar10 + 1) {
    if (bVar10 < 5) {
      if ((bVar10 != 2) && ((1 < bVar10 || (bVar10 != 0)))) {
LAB_80122c08:
        if (((FLOAT_803e1e3c <= (float)(&DAT_803a92ec)[bVar10]) &&
            (((((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0 && (DAT_803dd780 == '\0')) &&
              (DAT_803dd7d0 == 0)) &&
             ((iVar7 = FUN_8002073c(), iVar7 == 0 &&
              (iVar7 = (**(code **)(*DAT_803dca50 + 0x10))(), iVar7 != 0x44)))))) ||
           ((bVar10 == 3 && ((DAT_803dd792 & 2) != 0)))) {
          pfVar8 = (float *)(&DAT_803a92b8 + bVar10);
          fVar1 = FLOAT_803e1fa0 * FLOAT_803db414 + *pfVar8;
          *pfVar8 = fVar1;
          if (FLOAT_803e1ec0 < fVar1) {
            *pfVar8 = FLOAT_803e1ec0;
          }
        }
        else {
          pfVar8 = (float *)(&DAT_803a92b8 + bVar10);
          fVar1 = -(FLOAT_803e1fa0 * FLOAT_803db414 - *pfVar8);
          *pfVar8 = fVar1;
          if (fVar1 < FLOAT_803e1e3c) {
            *pfVar8 = FLOAT_803e1e3c;
          }
        }
      }
    }
    else if ((bVar10 < 0xd) && (9 < bVar10)) goto LAB_80122c08;
  }
  bVar10 = 0;
  local_60 = 0;
  if ((DAT_803dd840 & 1) == 0) {
    dVar13 = (double)FLOAT_803e1fa8;
    for (; bVar10 < 0xd; bVar10 = bVar10 + 1) {
      uVar2 = (uint)bVar10;
      pfVar8 = (float *)(&DAT_803a92ec + uVar2);
      dVar14 = (double)*pfVar8;
      dVar12 = (double)FLOAT_803db414;
      *pfVar8 = (float)(dVar14 - dVar12);
      if ((dVar13 < dVar14) && ((double)(float)(dVar14 - dVar12) <= dVar13)) {
        if (uVar2 == 3) {
          FUN_8000bb18(0,0x38d);
          piVar9 = &DAT_803a9364 + 3;
          iVar7 = *piVar9;
          iVar5 = local_78[3];
          if (iVar5 < iVar7) {
            *piVar9 = iVar7 + -1;
          }
          else {
            *piVar9 = iVar7 + 1;
          }
          if (*piVar9 != iVar5) {
            *pfVar8 = FLOAT_803e1fc4;
          }
        }
        else {
          (&DAT_803a9364)[uVar2] = local_78[uVar2];
        }
      }
      if ((local_78[uVar2] != 0) && ((&DAT_803a9354)[uVar2] == '\0')) {
        iVar5 = 0;
        switch(bVar10) {
        case 1:
          iVar5 = 0xb99;
          break;
        case 3:
          iVar5 = 0xb9c;
          break;
        case 4:
          iVar5 = 0xb98;
          break;
        case 10:
          iVar5 = 0xb9a;
          break;
        case 0xb:
          iVar5 = 0xb9b;
          break;
        case 0xc:
          iVar5 = 0xd97;
        }
        if (iVar5 != 0) {
          FUN_800200e8(iVar5,1);
          (&DAT_803a9354)[uVar2] = '\x01';
        }
      }
      if ((local_78[uVar2] != (&DAT_803a9320)[uVar2]) &&
         ((&DAT_803a9320)[uVar2] = local_78[uVar2], *pfVar8 <= FLOAT_803e1fa8)) {
        *pfVar8 = FLOAT_803e1fc8 - FLOAT_803db414;
      }
      if (bVar10 < 5) {
        if ((bVar10 != 2) && ((1 < bVar10 || (bVar10 != 0)))) goto LAB_80123098;
LAB_801230c0:
        if (*pfVar8 < FLOAT_803e1fbc) {
          *pfVar8 = FLOAT_803e1fbc;
        }
      }
      else {
        if ((0xc < bVar10) || (bVar10 < 10)) goto LAB_801230c0;
LAB_80123098:
        if (((double)FLOAT_803e1e3c < dVar14) && ((double)*pfVar8 <= (double)FLOAT_803e1e3c)) {
          *pfVar8 = FLOAT_803e1fc0;
        }
      }
    }
  }
  else {
    DAT_803dd840 = DAT_803dd840 & 0xfe;
    for (bVar10 = 0; fVar3 = FLOAT_803e1fbc, bVar10 < 7; bVar10 = bVar10 + 6) {
      iVar5 = local_78[bVar10];
      (&DAT_803a9364)[bVar10] = iVar5;
      (&DAT_803a9320)[bVar10] = iVar5;
      (&DAT_803a92ec)[bVar10] = fVar1;
      iVar5 = local_78[bVar10 + 1];
      (&DAT_803a9368)[bVar10] = iVar5;
      (&DAT_803a9324)[bVar10] = iVar5;
      (&DAT_803a92f0)[bVar10] = fVar1;
      iVar5 = local_78[bVar10 + 2];
      (&DAT_803a936c)[bVar10] = iVar5;
      (&DAT_803a9328)[bVar10] = iVar5;
      (&DAT_803a92f4)[bVar10] = fVar1;
      iVar5 = local_78[bVar10 + 3];
      (&DAT_803a9370)[bVar10] = iVar5;
      (&DAT_803a932c)[bVar10] = iVar5;
      (&DAT_803a92f8)[bVar10] = fVar1;
      iVar5 = local_78[bVar10 + 4];
      (&DAT_803a9374)[bVar10] = iVar5;
      (&DAT_803a9330)[bVar10] = iVar5;
      (&DAT_803a92fc)[bVar10] = fVar1;
      iVar5 = local_78[bVar10 + 5];
      (&DAT_803a9378)[bVar10] = iVar5;
      (&DAT_803a9334)[bVar10] = iVar5;
      (&DAT_803a9300)[bVar10] = fVar1;
    }
    for (; bVar10 < 0xd; bVar10 = bVar10 + 1) {
      iVar5 = local_78[bVar10];
      (&DAT_803a9364)[bVar10] = iVar5;
      (&DAT_803a9320)[bVar10] = iVar5;
      (&DAT_803a92ec)[bVar10] = fVar3;
    }
    iVar5 = FUN_8001ffb4(0xb98);
    if ((iVar5 != 0) || (local_68 != 0)) {
      DAT_803a92fc = FLOAT_803e1fc0;
    }
    iVar5 = FUN_8001ffb4(0xb99);
    if ((iVar5 != 0) || (local_78[1] != 0)) {
      DAT_803a92f0 = FLOAT_803e1fc0;
    }
    iVar5 = FUN_8001ffb4(0xb9a);
    if ((iVar5 != 0) || (local_50 != 0)) {
      DAT_803a9314 = FLOAT_803e1fc0;
    }
    iVar5 = FUN_8001ffb4(0xb9b);
    if ((iVar5 != 0) || (local_4c != 0)) {
      DAT_803a9318 = FLOAT_803e1fc0;
    }
    iVar5 = FUN_8001ffb4(0xb9c);
    if ((iVar5 != 0) || (local_78[3] != 0)) {
      DAT_803a92f8 = FLOAT_803e1fc0;
    }
    iVar5 = FUN_8001ffb4(0xd97);
    if ((iVar5 != 0) || (local_48 != 0)) {
      DAT_803a931c = FLOAT_803e1fc0;
    }
    FLOAT_803dd844 = FLOAT_803e1e3c;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  FUN_80286124();
  return;
}

