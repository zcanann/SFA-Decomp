// Function: FUN_800a07b0
// Entry: 800a07b0
// Size: 760 bytes

void FUN_800a07b0(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 local_18;
  undefined8 local_10;
  undefined8 local_8;
  
  dVar4 = DOUBLE_803e00c0;
  iVar6 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  if (param_3 == 1) {
    fVar1 = *(float *)(param_2 + 4);
    fVar2 = *(float *)(param_2 + 8);
    fVar3 = *(float *)(param_2 + 0xc);
    if (*(short *)(param_1 + 0xfe) == 0) {
      *(float *)(param_1 + 0xbc) = fVar1;
      *(float *)(param_1 + 0xc0) = fVar2;
      *(float *)(param_1 + 0xc4) = fVar3;
      fVar1 = FLOAT_803e00b0;
      *(float *)(param_1 + 200) = FLOAT_803e00b0;
      *(float *)(param_1 + 0xcc) = fVar1;
      *(float *)(param_1 + 0xd0) = fVar1;
    }
    else {
      *(float *)(param_1 + 0xbc) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xc)) - DOUBLE_803e00c0);
      *(float *)(param_1 + 0xc0) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xd)) - dVar4);
      *(float *)(param_1 + 0xc4) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xe)) - dVar4);
      dVar5 = DOUBLE_803e00c8;
      *(float *)(param_1 + 200) =
           (fVar1 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                     0x10 + 0xc)) - dVar4)) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
      local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
      *(float *)(param_1 + 0xcc) =
           (fVar2 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                     0x10 + 0xd)) - dVar4)) /
           (float)(local_18 - dVar5);
      local_10 = (double)CONCAT44(0x43300000,
                                  (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 + 0xe)
                                 );
      local_8 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
      *(float *)(param_1 + 0xd0) = (fVar3 - (float)(local_10 - dVar4)) / (float)(local_8 - dVar5);
    }
  }
  *(float *)(param_1 + 0xbc) = *(float *)(param_1 + 0xbc) + *(float *)(param_1 + 200);
  *(float *)(param_1 + 0xc0) = *(float *)(param_1 + 0xc0) + *(float *)(param_1 + 0xcc);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd0);
  if (FLOAT_803e00b0 <= *(float *)(param_1 + 0xbc)) {
    if (FLOAT_803e00bc < *(float *)(param_1 + 0xbc)) {
      *(float *)(param_1 + 0xbc) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(param_1 + 0xbc) = FLOAT_803e00b0;
  }
  if (FLOAT_803e00b0 <= *(float *)(param_1 + 0xc0)) {
    if (FLOAT_803e00bc < *(float *)(param_1 + 0xc0)) {
      *(float *)(param_1 + 0xc0) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(param_1 + 0xc0) = FLOAT_803e00b0;
  }
  if (FLOAT_803e00b0 <= *(float *)(param_1 + 0xc4)) {
    if (FLOAT_803e00bc < *(float *)(param_1 + 0xc4)) {
      *(float *)(param_1 + 0xc4) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(param_1 + 0xc4) = FLOAT_803e00b0;
  }
  iVar7 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xc) =
         (char)(int)*(float *)(param_1 + 0xbc);
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xd) =
         (char)(int)*(float *)(param_1 + 0xc0);
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xe) =
         (char)(int)*(float *)(param_1 + 0xc4);
    iVar7 = iVar7 + 2;
  }
  return;
}

