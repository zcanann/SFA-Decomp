// Function: FUN_801eae8c
// Entry: 801eae8c
// Size: 620 bytes

undefined4 FUN_801eae8c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  fVar1 = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc);
  fVar2 = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14);
  dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  dVar8 = (double)(float)((double)FLOAT_803e6800 - dVar8);
  dVar9 = (double)FLOAT_803e6780;
  if ((double)*(float *)(param_2 + 0x3e4) != dVar9) {
    dVar7 = (double)(float)(dVar8 - (double)FLOAT_803e67a8);
    if ((dVar9 <= dVar7) && (dVar9 = dVar7, (double)FLOAT_803e67a0 < dVar7)) {
      dVar9 = (double)FLOAT_803e67a0;
    }
    dVar8 = (double)(float)(dVar8 + dVar9);
  }
  if (dVar8 < (double)FLOAT_803e6780) {
    dVar8 = (double)FLOAT_803e6780;
  }
  iVar4 = (**(code **)(*DAT_803dd6ec + 0x18))
                    (dVar8,param_2,param_2 + 0x28,*(undefined *)(param_2 + 0x5d),1,0);
  (**(code **)(*DAT_803dd6ec + 0x14))(param_1,param_2 + 0x28);
  (**(code **)(*DAT_803dd6ec + 0x2c))(param_2 + 0x28);
  if (iVar4 == 0) {
    uVar6 = FUN_80021884();
    iVar4 = (uVar6 & 0xffff) - (uint)*(ushort *)(param_2 + 0x40c);
    if (0x8000 < iVar4) {
      iVar4 = iVar4 + -0xffff;
    }
    if (iVar4 < -0x8000) {
      iVar4 = iVar4 + 0xffff;
    }
    iVar3 = iVar4 / 0xb6 + (iVar4 >> 0x1f);
    iVar3 = iVar3 - (iVar3 >> 0x1f);
    if (iVar3 < -0x41) {
      iVar3 = -0x41;
    }
    else if (0x41 < iVar3) {
      iVar3 = 0x41;
    }
    *(float *)(param_2 + 0x45c) =
         (float)((double)CONCAT44(0x43300000,-iVar3 ^ 0x80000000) - DOUBLE_803e6798);
    *(undefined2 *)(param_2 + 0x44c) = 0;
    *(float *)(param_2 + 0x45c) = *(float *)(param_2 + 0x45c) / FLOAT_803e6804;
    fVar1 = *(float *)(param_2 + 0x45c);
    fVar2 = FLOAT_803e6808;
    if ((FLOAT_803e6808 <= fVar1) && (fVar2 = fVar1, FLOAT_803e6784 < fVar1)) {
      fVar2 = FLOAT_803e6784;
    }
    *(float *)(param_2 + 0x45c) = fVar2;
    dVar8 = FUN_801eacb0(param_1,param_2);
    if ((((double)*(float *)(param_2 + 0x49c) < -dVar8) || (0x2aaa < iVar4)) || (iVar4 < -0x2aaa)) {
      *(undefined4 *)(param_2 + 0x458) = 0;
    }
    else if (-dVar8 < (double)*(float *)(param_2 + 0x49c)) {
      *(undefined4 *)(param_2 + 0x458) = 0x100;
    }
    uVar5 = 1;
  }
  else {
    *(float *)(param_2 + 0x45c) = FLOAT_803e6780;
    uVar5 = 0;
  }
  return uVar5;
}

