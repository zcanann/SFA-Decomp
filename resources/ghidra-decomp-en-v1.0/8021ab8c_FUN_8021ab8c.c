// Function: FUN_8021ab8c
// Entry: 8021ab8c
// Size: 340 bytes

void FUN_8021ab8c(undefined2 *param_1,int param_2)

{
  float fVar1;
  double dVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_8021a638;
  if ((param_1[0x23] == 0x86a) || (param_1[0x23] == 0x86b)) {
    iVar4 = FUN_8001ffb4(0x609);
    if (iVar4 == 0) {
      param_1[3] = param_1[3] | 0x4000;
    }
  }
  else {
    FUN_80035f20();
    iVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
    if (iVar3 == 0) {
      FUN_800200e8(0x7aa,5);
    }
    else {
      FUN_80035f00(param_1);
      param_1[3] = param_1[3] | 0x4000;
      *(byte *)(iVar4 + 0x31) = *(byte *)(iVar4 + 0x31) & 0x7f | 0x80;
    }
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    dVar2 = DOUBLE_803e6a20;
    *(float *)(iVar4 + 8) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                DOUBLE_803e6a20);
    *(float *)(iVar4 + 0x10) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) - dVar2)
         / FLOAT_803e6a18;
    *(undefined4 *)(iVar4 + 4) = 0;
    fVar1 = FLOAT_803e6a1c;
    *(float *)(iVar4 + 0x14) = FLOAT_803e6a1c;
    *(float *)(iVar4 + 0x18) = fVar1;
    *(float *)(iVar4 + 0x1c) = fVar1;
    *(float *)(iVar4 + 0x20) = fVar1;
    FUN_80037200(param_1,0x18);
  }
  return;
}

