// Function: FUN_800a0c78
// Entry: 800a0c78
// Size: 856 bytes

void FUN_800a0c78(int param_1,int param_2,int param_3,uint param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double local_30;
  double local_18;
  double local_10;
  
  dVar4 = DOUBLE_803df448;
  if (param_3 == 1) {
    fVar1 = *(float *)(param_2 + 4);
    fVar2 = *(float *)(param_2 + 8);
    fVar3 = *(float *)(param_2 + 0xc);
    if ((int)*(short *)(param_1 + 0xfe) == 0) {
      iVar8 = *(int *)(param_1 + 0x80);
      iVar7 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
      iVar6 = 0;
      for (iVar5 = 0; iVar5 < *(short *)(param_2 + 0x14); iVar5 = iVar5 + 1) {
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar1);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 2;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar2);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 4;
        local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + iVar10) ^ 0x80000000);
        *(short *)(iVar8 + iVar10) = (short)(int)((float)(local_18 - dVar4) * fVar3);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 2;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 4;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar6 = iVar6 + 2;
      }
      return;
    }
    iVar6 = param_1 + (param_4 & 0xff) * 0x18;
    *(float *)(iVar6 + 0x3c) =
         (fVar1 - *(float *)(iVar6 + 0x30)) /
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                DOUBLE_803df448);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
    *(float *)(iVar6 + 0x40) = (fVar2 - *(float *)(iVar6 + 0x34)) / (float)(local_30 - dVar4);
    *(float *)(iVar6 + 0x44) =
         (fVar3 - *(float *)(iVar6 + 0x38)) /
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar4);
  }
  iVar5 = param_1 + (param_4 & 0xff) * 0x18;
  *(float *)(iVar5 + 0x30) = *(float *)(iVar5 + 0x3c) * FLOAT_803dd284 + *(float *)(iVar5 + 0x30);
  *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x40) * FLOAT_803dd284 + *(float *)(iVar5 + 0x34);
  *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x44) * FLOAT_803dd284 + *(float *)(iVar5 + 0x38);
  fVar1 = FLOAT_803df434;
  iVar7 = *(int *)(param_1 + 0x80);
  iVar6 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar10 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    if (fVar1 != *(float *)(iVar5 + 0x30)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x30) * (float)(local_10 - DOUBLE_803df448));
    }
    if (fVar1 != *(float *)(iVar5 + 0x34)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10 + 2;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x34) * (float)(local_10 - DOUBLE_803df448));
    }
    if (fVar1 != *(float *)(iVar5 + 0x38)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10 + 4;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x38) * (float)(local_10 - DOUBLE_803df448));
    }
    iVar10 = iVar10 + 2;
  }
  return;
}

