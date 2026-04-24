// Function: FUN_801eacb0
// Entry: 801eacb0
// Size: 476 bytes

/* WARNING: Removing unreachable block (ram,0x801eae6c) */
/* WARNING: Removing unreachable block (ram,0x801eae64) */
/* WARNING: Removing unreachable block (ram,0x801eacc8) */
/* WARNING: Removing unreachable block (ram,0x801eacc0) */

double FUN_801eacb0(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  double in_f30;
  double in_f31;
  
  if ((DAT_803dcd24 == -1) ||
     (iVar3 = (**(code **)(*DAT_803dd6ec + 0x34))(param_2 + 0x28), iVar3 < DAT_803dcd24)) {
    if (DAT_803dcd24 == -1) {
      iVar3 = FUN_8002bac4();
      dVar4 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
      fVar1 = (float)(dVar4 * (double)FLOAT_803e6790);
    }
    else {
      in_f31 = (double)(FLOAT_803e67e0 *
                        (float)((double)CONCAT44(0x43300000,DAT_803add04 ^ 0x80000000) -
                               DOUBLE_803e6798) + FLOAT_803e67e0 * DAT_803adcf4);
      in_f30 = (double)(FLOAT_803e67e0 *
                        (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x44) ^ 0x80000000)
                               - DOUBLE_803e6798) + FLOAT_803e67e0 * *(float *)(param_2 + 0x34));
      fVar1 = (float)(in_f31 - in_f30);
      if (fVar1 < FLOAT_803e6780) {
        fVar1 = -fVar1;
      }
    }
    fVar2 = *(float *)(param_2 + 0x1c);
    if (fVar2 < fVar1) {
      if (fVar1 < *(float *)(param_2 + 0x18)) {
        dVar4 = (double)(((fVar1 - fVar2) / (*(float *)(param_2 + 0x18) - fVar2)) *
                         (*(float *)(param_2 + 0x20) - *(float *)(param_2 + 0x24)) +
                        *(float *)(param_2 + 0x24));
      }
      else {
        dVar4 = (double)*(float *)(param_2 + 0x20);
      }
    }
    else {
      dVar4 = (double)*(float *)(param_2 + 0x24);
    }
    if (*(char *)(param_2 + 0x434) == '\0') {
      fVar1 = (float)(in_f30 - in_f31);
      if (fVar1 < FLOAT_803e6780) {
        fVar1 = -fVar1;
      }
      if (FLOAT_803dcd48 < fVar1) {
        dVar4 = (double)FLOAT_803e6780;
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dd6ec + 0x34))(param_2 + 0x28);
    if (iVar3 == 2) {
      dVar4 = (double)FLOAT_803e67f8;
    }
    else {
      dVar4 = (double)FLOAT_803e67fc;
    }
  }
  return dVar4;
}

