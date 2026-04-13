// Function: FUN_801ad2b0
// Entry: 801ad2b0
// Size: 204 bytes

double FUN_801ad2b0(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *local_18 [4];
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_80065fcc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,local_18,0,0);
  iVar6 = -1;
  iVar5 = 0;
  puVar4 = local_18[0];
  fVar1 = FLOAT_803e5398;
  if (0 < iVar3) {
    do {
      fVar2 = *(float *)(param_1 + 0x10) - *(float *)*puVar4;
      if ((FLOAT_803e539c < fVar2) && (fVar2 < fVar1)) {
        iVar6 = iVar5;
        fVar1 = fVar2;
      }
      puVar4 = puVar4 + 1;
      iVar5 = iVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (iVar6 == -1) {
    fVar1 = *(float *)(param_1 + 0x10);
  }
  else {
    *(undefined *)(iVar7 + 0xe) = 1;
    fVar1 = *(float *)local_18[0][iVar6];
  }
  return (double)fVar1;
}

