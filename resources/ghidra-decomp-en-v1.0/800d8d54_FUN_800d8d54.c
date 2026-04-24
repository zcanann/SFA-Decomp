// Function: FUN_800d8d54
// Entry: 800d8d54
// Size: 296 bytes

void FUN_800d8d54(short *param_1,int param_2,uint param_3)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_2 + 0x2d0);
  if (iVar4 != 0) {
    if (*(int *)(iVar4 + 0x30) == *(int *)(param_1 + 0x18)) {
      fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(param_1 + 6);
      fVar2 = *(float *)(iVar4 + 0x14) - *(float *)(param_1 + 10);
    }
    else {
      fVar1 = *(float *)(param_1 + 0xc) - *(float *)(iVar4 + 0x18);
      fVar2 = *(float *)(param_1 + 0x10) - *(float *)(iVar4 + 0x20);
    }
    uVar3 = FUN_800217c0(-(double)fVar1,-(double)fVar2);
    uVar3 = (uVar3 & 0xffff) - ((int)*param_1 & 0xffffU);
    if (0x8000 < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    if ((int)uVar3 < -0x8000) {
      uVar3 = uVar3 + 0xffff;
    }
    *param_1 = *param_1 +
               (short)(int)(((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                    DOUBLE_803e0598) * FLOAT_803db414) /
                           (FLOAT_803e0584 *
                           (float)((double)CONCAT44(0x43300000,param_3 ^ 0x80000000) -
                                  DOUBLE_803e0598)));
  }
  return;
}

