// Function: FUN_801accfc
// Entry: 801accfc
// Size: 204 bytes

double FUN_801accfc(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  float **ppfVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float **local_18 [4];
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,local_18,0,0);
  iVar6 = -1;
  iVar5 = 0;
  ppfVar4 = local_18[0];
  fVar1 = FLOAT_803e4700;
  if (0 < iVar3) {
    do {
      fVar2 = *(float *)(param_1 + 0x10) - **ppfVar4;
      if ((FLOAT_803e4704 < fVar2) && (fVar2 < fVar1)) {
        iVar6 = iVar5;
        fVar1 = fVar2;
      }
      ppfVar4 = ppfVar4 + 1;
      iVar5 = iVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (iVar6 == -1) {
    fVar1 = *(float *)(param_1 + 0x10);
  }
  else {
    *(undefined *)(iVar7 + 0xe) = 1;
    fVar1 = *local_18[0][iVar6];
  }
  return (double)fVar1;
}

