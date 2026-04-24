// Function: FUN_8021b234
// Entry: 8021b234
// Size: 340 bytes

void FUN_8021b234(undefined2 *param_1,int param_2)

{
  float fVar1;
  double dVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_8021ace0;
  if ((param_1[0x23] == 0x86a) || (param_1[0x23] == 0x86b)) {
    uVar3 = FUN_80020078(0x609);
    if (uVar3 == 0) {
      param_1[3] = param_1[3] | 0x4000;
    }
  }
  else {
    FUN_80036018((int)param_1);
    uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
    if (uVar3 == 0) {
      FUN_800201ac(0x7aa,5);
    }
    else {
      FUN_80035ff8((int)param_1);
      param_1[3] = param_1[3] | 0x4000;
      *(byte *)(iVar4 + 0x31) = *(byte *)(iVar4 + 0x31) & 0x7f | 0x80;
    }
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    dVar2 = DOUBLE_803e76b8;
    *(float *)(iVar4 + 8) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                DOUBLE_803e76b8);
    *(float *)(iVar4 + 0x10) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) - dVar2)
         / FLOAT_803e76b0;
    *(undefined4 *)(iVar4 + 4) = 0;
    fVar1 = FLOAT_803e76b4;
    *(float *)(iVar4 + 0x14) = FLOAT_803e76b4;
    *(float *)(iVar4 + 0x18) = fVar1;
    *(float *)(iVar4 + 0x1c) = fVar1;
    *(float *)(iVar4 + 0x20) = fVar1;
    FUN_800372f8((int)param_1,0x18);
  }
  return;
}

