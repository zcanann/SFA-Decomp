// Function: FUN_800222e4
// Entry: 800222e4
// Size: 288 bytes

void FUN_800222e4(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float *pfVar12;
  float *pfVar13;
  float *pfVar14;
  
  pfVar13 = param_1;
  do {
    pfVar14 = param_3;
    pfVar12 = pfVar13;
    fVar1 = *pfVar12;
    fVar2 = pfVar12[1];
    fVar3 = pfVar12[2];
    fVar4 = param_2[1];
    fVar5 = param_2[5];
    fVar6 = param_2[9];
    *pfVar14 = fVar3 * param_2[8] + fVar1 * *param_2 + fVar2 * param_2[4];
    fVar7 = param_2[2];
    fVar8 = param_2[6];
    fVar9 = param_2[10];
    pfVar14[1] = fVar3 * fVar6 + fVar1 * fVar4 + fVar2 * fVar5;
    pfVar14[2] = fVar3 * fVar9 + fVar1 * fVar7 + fVar2 * fVar8;
    pfVar13 = pfVar12 + 4;
    param_3 = pfVar14 + 4;
  } while (param_1 + 0xc != pfVar13);
  fVar1 = *pfVar13;
  fVar2 = pfVar12[5];
  fVar3 = pfVar12[6];
  fVar4 = param_2[1];
  fVar5 = param_2[5];
  fVar6 = param_2[9];
  fVar7 = param_2[0xd];
  pfVar14[4] = fVar2 * param_2[4] + fVar3 * param_2[8] + fVar1 * *param_2 + param_2[0xc];
  fVar8 = param_2[2];
  fVar9 = param_2[6];
  fVar10 = param_2[10];
  fVar11 = param_2[0xe];
  pfVar14[5] = fVar2 * fVar5 + fVar3 * fVar6 + fVar1 * fVar4 + fVar7;
  pfVar14[6] = fVar2 * fVar9 + fVar3 * fVar10 + fVar1 * fVar8 + fVar11;
  return;
}

