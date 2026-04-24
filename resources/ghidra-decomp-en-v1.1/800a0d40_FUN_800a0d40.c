// Function: FUN_800a0d40
// Entry: 800a0d40
// Size: 452 bytes

void FUN_800a0d40(int param_1,int param_2,int param_3,uint param_4)

{
  float fVar1;
  double dVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 local_8;
  
  dVar2 = DOUBLE_803e00c0;
  iVar5 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar6 = *(int *)(param_1 + 0x80);
  if (param_3 == 1) {
    fVar1 = *(float *)(param_2 + 4);
    if ((int)*(short *)(param_1 + 0xfe) == 0) {
      iVar7 = 0;
      for (iVar3 = 0; iVar3 < *(short *)(param_2 + 0x14); iVar3 = iVar3 + 1) {
        *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xf) =
             (char)(int)fVar1;
        iVar8 = *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xf;
        *(undefined *)(iVar5 + iVar8) = *(undefined *)(iVar6 + iVar8);
        iVar7 = iVar7 + 2;
      }
      return;
    }
    iVar7 = param_1 + (param_4 & 0xff) * 8;
    *(float *)(iVar7 + 0xac) =
         (fVar1 - (float)((double)CONCAT44(0x43300000,
                                           (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                   0x10 + 0xf)) - DOUBLE_803e00c0))
         / (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
    local_8 = (double)CONCAT44(0x43300000,
                               (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 + 0xf));
    *(float *)(iVar7 + 0xb0) = (float)(local_8 - dVar2);
  }
  iVar7 = (param_4 & 0xff) * 8;
  iVar3 = param_1 + iVar7;
  *(float *)(iVar3 + 0xb0) = *(float *)(iVar3 + 0xac) * FLOAT_803ddf04 + *(float *)(iVar3 + 0xb0);
  if (FLOAT_803e00b0 <= *(float *)(iVar3 + 0xb0)) {
    if (FLOAT_803e00bc < *(float *)(iVar3 + 0xb0)) {
      *(float *)(iVar3 + 0xb0) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(iVar3 + 0xb0) = FLOAT_803e00b0;
  }
  iVar3 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    *(char *)(iVar5 + *(short *)(*(int *)(param_2 + 0x10) + iVar3) * 0x10 + 0xf) =
         (char)(int)*(float *)(param_1 + iVar7 + 0xb0);
    iVar4 = *(short *)(*(int *)(param_2 + 0x10) + iVar3) * 0x10 + 0xf;
    *(undefined *)(iVar6 + iVar4) = *(undefined *)(iVar5 + iVar4);
    iVar3 = iVar3 + 2;
  }
  return;
}

