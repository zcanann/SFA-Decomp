// Function: FUN_801ea854
// Entry: 801ea854
// Size: 620 bytes

undefined4 FUN_801ea854(int param_1,int param_2)

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
  dVar8 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
  dVar8 = (double)(float)((double)FLOAT_803e5b68 - dVar8);
  dVar9 = (double)FLOAT_803e5ae8;
  if ((double)*(float *)(param_2 + 0x3e4) != dVar9) {
    dVar7 = (double)(float)(dVar8 - (double)FLOAT_803e5b10);
    if ((dVar9 <= dVar7) && (dVar9 = dVar7, (double)FLOAT_803e5b08 < dVar7)) {
      dVar9 = (double)FLOAT_803e5b08;
    }
    dVar8 = (double)(float)(dVar8 + dVar9);
  }
  if (dVar8 < (double)FLOAT_803e5ae8) {
    dVar8 = (double)FLOAT_803e5ae8;
  }
  iVar4 = (**(code **)(*DAT_803dca6c + 0x18))
                    (dVar8,param_2,param_2 + 0x28,*(undefined *)(param_2 + 0x5d),1,0);
  (**(code **)(*DAT_803dca6c + 0x14))(param_1,param_2 + 0x28);
  (**(code **)(*DAT_803dca6c + 0x2c))(param_2 + 0x28);
  if (iVar4 == 0) {
    uVar6 = FUN_800217c0((double)(*(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc)),
                         (double)(*(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14)));
    iVar4 = (uVar6 & 0xffff) - ((int)*(short *)(param_2 + 0x40c) & 0xffffU);
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
         (float)((double)CONCAT44(0x43300000,-iVar3 ^ 0x80000000) - DOUBLE_803e5b00);
    *(undefined2 *)(param_2 + 0x44c) = 0;
    *(float *)(param_2 + 0x45c) = *(float *)(param_2 + 0x45c) / FLOAT_803e5b6c;
    fVar1 = *(float *)(param_2 + 0x45c);
    fVar2 = FLOAT_803e5b70;
    if ((FLOAT_803e5b70 <= fVar1) && (fVar2 = fVar1, FLOAT_803e5aec < fVar1)) {
      fVar2 = FLOAT_803e5aec;
    }
    *(float *)(param_2 + 0x45c) = fVar2;
    dVar8 = (double)FUN_801ea678(param_1,param_2);
    if ((((double)*(float *)(param_2 + 0x49c) < -dVar8) || (0x2aaa < iVar4)) || (iVar4 < -0x2aaa)) {
      *(undefined4 *)(param_2 + 0x458) = 0;
    }
    else if (-dVar8 < (double)*(float *)(param_2 + 0x49c)) {
      *(undefined4 *)(param_2 + 0x458) = 0x100;
    }
    uVar5 = 1;
  }
  else {
    *(float *)(param_2 + 0x45c) = FLOAT_803e5ae8;
    uVar5 = 0;
  }
  return uVar5;
}

