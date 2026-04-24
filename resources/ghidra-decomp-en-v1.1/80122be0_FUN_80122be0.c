// Function: FUN_80122be0
// Entry: 80122be0
// Size: 2064 bytes

/* WARNING: Removing unreachable block (ram,0x801233d0) */
/* WARNING: Removing unreachable block (ram,0x801233c8) */
/* WARNING: Removing unreachable block (ram,0x80122bf8) */
/* WARNING: Removing unreachable block (ram,0x80122bf0) */

void FUN_80122be0(void)

{
  float fVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  byte *pbVar5;
  int iVar6;
  uint uVar7;
  float *pfVar8;
  uint uVar9;
  byte bVar10;
  double dVar11;
  double dVar12;
  double in_f30;
  double dVar13;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  int local_78 [4];
  uint local_68;
  undefined4 local_60;
  int local_5c;
  int local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  FUN_8028683c();
  iVar4 = FUN_8002bac4();
  FUN_8002ba84();
  pbVar5 = (byte *)(**(code **)(*DAT_803dd72c + 0x94))();
  local_78[0] = FUN_80297248(iVar4);
  local_5c = FUN_80297234(iVar4);
  local_78[1] = FUN_80020078(0xc1);
  iVar6 = FUN_80297174(iVar4);
  if (DAT_803a9f88 - iVar6 < 0) {
    local_78[2] = -1;
  }
  else {
    iVar6 = FUN_80297174(iVar4);
    if (DAT_803a9f88 - iVar6 < 1) {
      local_78[2] = 0;
    }
    else {
      local_78[2] = 1;
    }
  }
  local_78[2] = DAT_803a9f88 - local_78[2];
  iVar6 = FUN_802971ec(iVar4);
  if (DAT_803a9fa0 - iVar6 < 0) {
    cVar3 = -1;
  }
  else {
    iVar6 = FUN_802971ec(iVar4);
    if (DAT_803a9fa0 - iVar6 < 1) {
      cVar3 = '\0';
    }
    else {
      cVar3 = '\x01';
    }
  }
  local_58 = DAT_803a9fa0 + -cVar3;
  if ((((-cVar3 != 0) && (FLOAT_803de4bc != FLOAT_803e2abc)) &&
      (uVar7 = FUN_80296328(iVar4), uVar7 != 0)) && (uVar7 = FUN_80020078(0xeb1), uVar7 != 0)) {
    FUN_8000da78(0,0x3f0);
  }
  DAT_803a9fcc = local_78[2];
  DAT_803a9fe4 = local_58;
  local_68 = FUN_80020078(0x66c);
  local_50 = FUN_80020078(0x13d);
  if (local_50 != DAT_803a9fa8) {
    FUN_800201ac(0x967,(uint)(local_50 == 0));
  }
  local_4c = FUN_80020078(0x86a);
  local_48 = FUN_80020078(0x3f5);
  local_78[3] = FUN_80296ffc(iVar4);
  local_54 = (uint)*pbVar5;
  if ((((DAT_803de412 & 1) == 0) &&
      (((dVar12 = (double)(**(code **)(*DAT_803dd6cc + 0x18))(), (double)FLOAT_803e2abc != dVar12 ||
        (iVar6 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar6 == 0x44)) ||
       (((*(ushort *)(iVar4 + 0xb0) & 0x1000) != 0 ||
        ((iVar6 = FUN_80020800(), iVar6 != 0 || (DAT_803de3db != '\0')))))))) ||
     (DAT_803de400 != '\0')) {
    FLOAT_803de4bc = -(FLOAT_803e2c20 * FLOAT_803dc074 - FLOAT_803de4bc);
    if (FLOAT_803de4bc < FLOAT_803e2abc) {
      FLOAT_803de4bc = FLOAT_803e2abc;
    }
  }
  else {
    FLOAT_803de4bc = FLOAT_803e2c20 * FLOAT_803dc074 + FLOAT_803de4bc;
    if (FLOAT_803e2b40 < FLOAT_803de4bc) {
      FLOAT_803de4bc = FLOAT_803e2b40;
    }
  }
  if ((DAT_803de413 == '\0') && (uVar7 = FUN_80020078(0xa7b), uVar7 != 0)) {
    DAT_803de413 = '\x01';
  }
  for (bVar10 = 0; fVar1 = FLOAT_803e2c3c, bVar10 < 0xd; bVar10 = bVar10 + 1) {
    if (bVar10 < 5) {
      if ((bVar10 != 2) && ((1 < bVar10 || (bVar10 != 0)))) {
LAB_80122eec:
        if (((FLOAT_803e2abc <= (float)(&DAT_803a9f4c)[bVar10]) &&
            (((((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0 && (DAT_803de400 == '\0')) &&
              (DAT_803de450 == 0)) &&
             ((iVar6 = FUN_80020800(), iVar6 == 0 &&
              (iVar6 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar6 != 0x44)))))) ||
           ((bVar10 == 3 && ((DAT_803de412 & 2) != 0)))) {
          pfVar8 = (float *)(&DAT_803a9f18 + bVar10);
          fVar1 = FLOAT_803e2c20 * FLOAT_803dc074 + *pfVar8;
          *pfVar8 = fVar1;
          if (FLOAT_803e2b40 < fVar1) {
            *pfVar8 = FLOAT_803e2b40;
          }
        }
        else {
          pfVar8 = (float *)(&DAT_803a9f18 + bVar10);
          fVar1 = -(FLOAT_803e2c20 * FLOAT_803dc074 - *pfVar8);
          *pfVar8 = fVar1;
          if (fVar1 < FLOAT_803e2abc) {
            *pfVar8 = FLOAT_803e2abc;
          }
        }
      }
    }
    else if ((bVar10 < 0xd) && (9 < bVar10)) goto LAB_80122eec;
  }
  bVar10 = 0;
  local_60 = 0;
  if ((DAT_803de4c0 & 1) == 0) {
    dVar12 = (double)FLOAT_803e2c28;
    for (; bVar10 < 0xd; bVar10 = bVar10 + 1) {
      uVar7 = (uint)bVar10;
      pfVar8 = (float *)(&DAT_803a9f4c + uVar7);
      dVar13 = (double)*pfVar8;
      dVar11 = (double)FLOAT_803dc074;
      *pfVar8 = (float)(dVar13 - dVar11);
      if ((dVar12 < dVar13) && ((double)(float)(dVar13 - dVar11) <= dVar12)) {
        if (uVar7 == 3) {
          FUN_8000bb38(0,0x38d);
          if (local_78[3] < DAT_803a9fd0) {
            DAT_803a9fd0 = DAT_803a9fd0 + -1;
          }
          else {
            DAT_803a9fd0 = DAT_803a9fd0 + 1;
          }
          if (DAT_803a9fd0 != local_78[3]) {
            *pfVar8 = FLOAT_803e2c44;
          }
        }
        else {
          (&DAT_803a9fc4)[uVar7] = local_78[uVar7];
        }
      }
      if ((local_78[uVar7] != 0) && ((&DAT_803a9fb4)[uVar7] == '\0')) {
        uVar9 = 0;
        switch(bVar10) {
        case 1:
          uVar9 = 0xb99;
          break;
        case 3:
          uVar9 = 0xb9c;
          break;
        case 4:
          uVar9 = 0xb98;
          break;
        case 10:
          uVar9 = 0xb9a;
          break;
        case 0xb:
          uVar9 = 0xb9b;
          break;
        case 0xc:
          uVar9 = 0xd97;
        }
        if (uVar9 != 0) {
          FUN_800201ac(uVar9,1);
          (&DAT_803a9fb4)[uVar7] = '\x01';
        }
      }
      if ((local_78[uVar7] != (&DAT_803a9f80)[uVar7]) &&
         ((&DAT_803a9f80)[uVar7] = local_78[uVar7], *pfVar8 <= FLOAT_803e2c28)) {
        *pfVar8 = FLOAT_803e2c48 - FLOAT_803dc074;
      }
      if (bVar10 < 5) {
        if ((bVar10 != 2) && ((1 < bVar10 || (bVar10 != 0)))) goto LAB_8012337c;
LAB_801233a4:
        if (*pfVar8 < FLOAT_803e2c3c) {
          *pfVar8 = FLOAT_803e2c3c;
        }
      }
      else {
        if ((0xc < bVar10) || (bVar10 < 10)) goto LAB_801233a4;
LAB_8012337c:
        if (((double)FLOAT_803e2abc < dVar13) && ((double)*pfVar8 <= (double)FLOAT_803e2abc)) {
          *pfVar8 = FLOAT_803e2c40;
        }
      }
    }
  }
  else {
    DAT_803de4c0 = DAT_803de4c0 & 0xfe;
    for (bVar10 = 0; fVar2 = FLOAT_803e2c3c, bVar10 < 7; bVar10 = bVar10 + 6) {
      iVar4 = local_78[bVar10];
      (&DAT_803a9fc4)[bVar10] = iVar4;
      (&DAT_803a9f80)[bVar10] = iVar4;
      (&DAT_803a9f4c)[bVar10] = fVar1;
      iVar4 = local_78[bVar10 + 1];
      (&DAT_803a9fc8)[bVar10] = iVar4;
      (&DAT_803a9f84)[bVar10] = iVar4;
      (&DAT_803a9f50)[bVar10] = fVar1;
      iVar4 = local_78[bVar10 + 2];
      (&DAT_803a9fcc)[bVar10] = iVar4;
      (&DAT_803a9f88)[bVar10] = iVar4;
      (&DAT_803a9f54)[bVar10] = fVar1;
      iVar4 = local_78[bVar10 + 3];
      (&DAT_803a9fd0)[bVar10] = iVar4;
      (&DAT_803a9f8c)[bVar10] = iVar4;
      (&DAT_803a9f58)[bVar10] = fVar1;
      iVar4 = local_78[bVar10 + 4];
      (&DAT_803a9fd4)[bVar10] = iVar4;
      (&DAT_803a9f90)[bVar10] = iVar4;
      (&DAT_803a9f5c)[bVar10] = fVar1;
      iVar4 = local_78[bVar10 + 5];
      (&DAT_803a9fd8)[bVar10] = iVar4;
      (&DAT_803a9f94)[bVar10] = iVar4;
      (&DAT_803a9f60)[bVar10] = fVar1;
    }
    for (; bVar10 < 0xd; bVar10 = bVar10 + 1) {
      iVar4 = local_78[bVar10];
      (&DAT_803a9fc4)[bVar10] = iVar4;
      (&DAT_803a9f80)[bVar10] = iVar4;
      (&DAT_803a9f4c)[bVar10] = fVar2;
    }
    uVar7 = FUN_80020078(0xb98);
    if ((uVar7 != 0) || (local_68 != 0)) {
      DAT_803a9f5c = FLOAT_803e2c40;
    }
    uVar7 = FUN_80020078(0xb99);
    if ((uVar7 != 0) || (local_78[1] != 0)) {
      DAT_803a9f50 = FLOAT_803e2c40;
    }
    uVar7 = FUN_80020078(0xb9a);
    if ((uVar7 != 0) || (local_50 != 0)) {
      DAT_803a9f74 = FLOAT_803e2c40;
    }
    uVar7 = FUN_80020078(0xb9b);
    if ((uVar7 != 0) || (local_4c != 0)) {
      DAT_803a9f78 = FLOAT_803e2c40;
    }
    uVar7 = FUN_80020078(0xb9c);
    if ((uVar7 != 0) || (local_78[3] != 0)) {
      DAT_803a9f58 = FLOAT_803e2c40;
    }
    uVar7 = FUN_80020078(0xd97);
    if ((uVar7 != 0) || (local_48 != 0)) {
      DAT_803a9f7c = FLOAT_803e2c40;
    }
    FLOAT_803de4c4 = FLOAT_803e2abc;
  }
  FUN_80286888();
  return;
}

