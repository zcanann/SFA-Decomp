// Function: FUN_80022404
// Entry: 80022404
// Size: 588 bytes

void FUN_80022404(int param_1,int param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  float local_58 [5];
  float fStack68;
  float fStack64;
  float fStack60;
  float local_38;
  float fStack52;
  float fStack48;
  float fStack44;
  float local_28;
  float fStack36;
  float fStack32;
  float fStack28;
  
  iVar9 = 0;
  iVar10 = 0;
  iVar5 = 0;
  do {
    iVar8 = 0;
    iVar7 = 0;
    iVar6 = iVar10 << 2;
    iVar11 = 2;
    do {
      *(float *)((int)local_58 + iVar6) = FLOAT_803de7c0;
      fVar1 = *(float *)(param_1 + iVar5);
      *(float *)((int)local_58 + iVar6) =
           fVar1 * *(float *)(param_2 + iVar7) + *(float *)((int)local_58 + iVar6);
      fVar2 = *(float *)(param_1 + (iVar10 + 1) * 4);
      *(float *)((int)local_58 + iVar6) =
           fVar2 * *(float *)(param_2 + (iVar8 + 4) * 4) + *(float *)((int)local_58 + iVar6);
      fVar3 = *(float *)(param_1 + (iVar10 + 2) * 4);
      *(float *)((int)local_58 + iVar6) =
           fVar3 * *(float *)(param_2 + (iVar8 + 8) * 4) + *(float *)((int)local_58 + iVar6);
      fVar4 = *(float *)(param_1 + (iVar10 + 3) * 4);
      *(float *)((int)local_58 + iVar6) =
           fVar4 * *(float *)(param_2 + (iVar8 + 0xc) * 4) + *(float *)((int)local_58 + iVar6);
      *(float *)((int)local_58 + iVar6 + 4) = FLOAT_803de7c0;
      *(float *)((int)local_58 + iVar6 + 4) =
           fVar1 * *(float *)(param_2 + iVar7 + 4) + *(float *)((int)local_58 + iVar6 + 4);
      *(float *)((int)local_58 + iVar6 + 4) =
           fVar2 * *(float *)(param_2 + (iVar8 + 5) * 4) + *(float *)((int)local_58 + iVar6 + 4);
      *(float *)((int)local_58 + iVar6 + 4) =
           fVar3 * *(float *)(param_2 + (iVar8 + 9) * 4) + *(float *)((int)local_58 + iVar6 + 4);
      *(float *)((int)local_58 + iVar6 + 4) =
           fVar4 * *(float *)(param_2 + (iVar8 + 0xd) * 4) + *(float *)((int)local_58 + iVar6 + 4);
      iVar6 = iVar6 + 8;
      iVar8 = iVar8 + 2;
      iVar7 = iVar7 + 8;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    iVar10 = iVar10 + 4;
    iVar5 = iVar5 + 0x10;
    iVar9 = iVar9 + 1;
  } while (iVar9 < 4);
  *param_3 = local_58[0];
  param_3[1] = local_58[1];
  param_3[2] = local_58[2];
  param_3[3] = local_58[3];
  param_3[4] = local_58[4];
  param_3[5] = fStack68;
  param_3[6] = fStack64;
  param_3[7] = fStack60;
  param_3[8] = local_38;
  param_3[9] = fStack52;
  param_3[10] = fStack48;
  param_3[0xb] = fStack44;
  param_3[0xc] = local_28;
  param_3[0xd] = fStack36;
  param_3[0xe] = fStack32;
  param_3[0xf] = fStack28;
  return;
}

