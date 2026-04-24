// Function: FUN_80141290
// Entry: 80141290
// Size: 1516 bytes

/* WARNING: Removing unreachable block (ram,0x80141570) */
/* WARNING: Removing unreachable block (ram,0x80141588) */
/* WARNING: Removing unreachable block (ram,0x8014185c) */

void FUN_80141290(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f31;
  undefined8 uVar14;
  int local_48 [5];
  uint uStack52;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar14 = FUN_802860d4();
  iVar4 = (int)((ulonglong)uVar14 >> 0x20);
  iVar3 = (int)uVar14;
  iVar8 = 0;
  if (*(char *)(iVar3 + 10) == '\0') {
    FUN_8013b368((double)FLOAT_803e2488);
    iVar8 = FUN_800dbcfc(*(int *)(iVar3 + 0x700) + 8,0);
    iVar4 = FUN_800dbcfc(iVar4 + 0x18,0);
    if (iVar4 == iVar8) {
      uVar10 = *(undefined4 *)(iVar3 + 0x700);
      (**(code **)(*DAT_803dca9c + 0x54))(uVar10,0);
      iVar4 = (**(code **)(*DAT_803dca9c + 0x1c))();
      (**(code **)(*DAT_803dca9c + 0x60))(uVar10,0);
      iVar8 = (**(code **)(*DAT_803dca9c + 0x1c))();
      dVar12 = (double)FUN_8002166c(*(int *)(iVar3 + 4) + 0x18,iVar4 + 8);
      dVar13 = (double)FUN_8002166c(*(int *)(iVar3 + 4) + 0x18,iVar8 + 8);
      if (dVar12 <= dVar13) {
        (**(code **)(*DAT_803dca9c + 0x60))(iVar8,0);
        uVar5 = (**(code **)(*DAT_803dca9c + 0x1c))();
        *(undefined4 *)(iVar3 + 0x4a0) = 1;
      }
      else {
        (**(code **)(*DAT_803dca9c + 0x54))(iVar4,0);
        uVar5 = (**(code **)(*DAT_803dca9c + 0x1c))();
        *(undefined4 *)(iVar3 + 0x4a0) = 0;
        iVar8 = iVar4;
      }
      FUN_800da980(iVar3 + 0x420,uVar10,iVar8,uVar5);
      if (*(int *)(iVar3 + 0x4a0) == 0) {
        FUN_800da928((double)FLOAT_803e23e0,iVar3 + 0x420);
      }
      else {
        FUN_800da928((double)FLOAT_803e250c,iVar3 + 0x420);
      }
      *(float *)(iVar3 + 0x708) = FLOAT_803e23dc;
      *(undefined *)(iVar3 + 10) = 1;
    }
  }
  else {
    if (*(int *)(iVar3 + 0x4a0) == 0) {
      if (*(int *)(iVar3 + 0x430) != 0) {
        iVar6 = *(int *)(iVar3 + 0x4c4);
        if ((-1 < *(int *)(iVar6 + 0x1c)) && ((*(byte *)(iVar6 + 0x1b) & 1) == 0)) {
          iVar8 = 1;
          local_48[0] = *(int *)(iVar6 + 0x1c);
        }
        iVar9 = iVar8;
        if ((-1 < *(int *)(iVar6 + 0x20)) && ((*(byte *)(iVar6 + 0x1b) & 2) == 0)) {
          iVar9 = iVar8 + 1;
          local_48[iVar8] = *(int *)(iVar6 + 0x20);
        }
        iVar8 = iVar9;
        if ((-1 < *(int *)(iVar6 + 0x24)) && ((*(byte *)(iVar6 + 0x1b) & 4) == 0)) {
          iVar8 = iVar9 + 1;
          local_48[iVar9] = *(int *)(iVar6 + 0x24);
        }
        if ((-1 < *(int *)(iVar6 + 0x28)) && ((*(byte *)(iVar6 + 0x1b) & 8) == 0)) {
          local_48[iVar8] = *(int *)(iVar6 + 0x28);
          iVar8 = iVar8 + 1;
        }
      }
    }
    else if (*(int *)(iVar3 + 0x430) == 0) {
      iVar6 = *(int *)(iVar3 + 0x4c4);
      if ((-1 < *(int *)(iVar6 + 0x1c)) && ((*(byte *)(iVar6 + 0x1b) & 1) != 0)) {
        iVar8 = 1;
        local_48[0] = *(int *)(iVar6 + 0x1c);
      }
      iVar9 = iVar8;
      if ((-1 < *(int *)(iVar6 + 0x20)) && ((*(byte *)(iVar6 + 0x1b) & 2) != 0)) {
        iVar9 = iVar8 + 1;
        local_48[iVar8] = *(int *)(iVar6 + 0x20);
      }
      iVar2 = iVar9;
      if ((-1 < *(int *)(iVar6 + 0x24)) && ((*(byte *)(iVar6 + 0x1b) & 4) != 0)) {
        iVar2 = iVar9 + 1;
        local_48[iVar9] = *(int *)(iVar6 + 0x24);
      }
      iVar8 = iVar2;
      if ((-1 < *(int *)(iVar6 + 0x28)) && ((*(byte *)(iVar6 + 0x1b) & 8) != 0)) {
        iVar8 = iVar2 + 1;
        local_48[iVar2] = *(int *)(iVar6 + 0x28);
      }
    }
    if (iVar8 != 0) {
      iVar6 = (**(code **)(*DAT_803dca9c + 0x1c))(local_48[0]);
      dVar12 = (double)FUN_8002166c(*(int *)(iVar3 + 0x24) + 0x18,iVar6 + 8);
      piVar7 = local_48;
      for (iVar9 = 1; piVar7 = piVar7 + 1, iVar9 < iVar8; iVar9 = iVar9 + 1) {
        iVar2 = (**(code **)(*DAT_803dca9c + 0x1c))(*piVar7);
        dVar13 = (double)FUN_8002166c(*(int *)(iVar3 + 0x24) + 0x18,iVar2 + 8);
        if (dVar13 < dVar12) {
          iVar6 = iVar2;
          dVar12 = dVar13;
        }
      }
      FUN_800da23c(iVar3 + 0x420,iVar6);
    }
    fVar1 = *(float *)(iVar3 + 0x14);
    if (fVar1 <= FLOAT_803e2508) {
      fVar1 = FLOAT_803e2420 * FLOAT_803db414 + fVar1;
      if (FLOAT_803e2508 < fVar1) {
        fVar1 = FLOAT_803e2508;
      }
    }
    else {
      fVar1 = FLOAT_803e241c * FLOAT_803db414 + fVar1;
      if (fVar1 < FLOAT_803e2508) {
        fVar1 = FLOAT_803e2508;
      }
    }
    *(float *)(iVar3 + 0x14) = fVar1;
    FUN_80139834((double)*(float *)(iVar3 + 0x14),iVar4,iVar3 + 0x420);
    FUN_80139a8c(iVar4,iVar3 + 0x488);
    iVar8 = FUN_800dbcfc(iVar4 + 0x18,0);
    if (iVar8 == 0) {
      *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) | 0x10;
    }
    else {
      *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) & 0xffffffef;
    }
    *(float *)(iVar3 + 0x708) = *(float *)(iVar3 + 0x708) - FLOAT_803db414;
    if (*(float *)(iVar3 + 0x708) < FLOAT_803e23dc) {
      uStack52 = FUN_800221a0(200,600);
      uStack52 = uStack52 ^ 0x80000000;
      local_48[4] = 0x43300000;
      *(float *)(iVar3 + 0x708) = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e2460);
      iVar8 = *(int *)(iVar4 + 0xb8);
      if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(iVar4 + 0xa0) || (*(short *)(iVar4 + 0xa0) < 0x29)) &&
          (iVar3 = FUN_8000b578(iVar4,0x10), iVar3 == 0)))) {
        FUN_800393f8(iVar4,iVar8 + 0x3a8,0x29b,0x1000,0xffffffff,0);
      }
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286120();
  return;
}

