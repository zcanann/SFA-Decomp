// Function: FUN_801e963c
// Entry: 801e963c
// Size: 408 bytes

void FUN_801e963c(short *param_1,int param_2)

{
  undefined2 uVar2;
  int iVar1;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_1 + 0x5c);
  param_1[0x58] = param_1[0x58] | 0x2000;
  param_1[0x58] = param_1[0x58] | 0x4000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if ((int)*(short *)(param_2 + 0x1a) != 0) {
    *(float *)(param_1 + 4) =
         FLOAT_803e5ac0 *
         ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                 DOUBLE_803e5ad0) / FLOAT_803e5ac4);
  }
  *pfVar3 = FLOAT_803e5abc;
  dVar4 = (double)FUN_80293e80((double)((FLOAT_803e5ac8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e5ad0)) / FLOAT_803e5acc));
  pfVar3[1] = (float)dVar4;
  dVar4 = (double)FUN_80294204((double)((FLOAT_803e5ac8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e5ad0)) / FLOAT_803e5acc));
  pfVar3[2] = (float)dVar4;
  pfVar3[3] = -(pfVar3[1] * *(float *)(param_1 + 6) + pfVar3[2] * *(float *)(param_1 + 10));
  uVar2 = FUN_800221a0(0xb4,300);
  *(undefined2 *)(pfVar3 + 5) = uVar2;
  iVar1 = FUN_8002b9ec();
  if (iVar1 != 0) {
    if (FLOAT_803e5aa0 <=
        pfVar3[3] + pfVar3[1] * *(float *)(iVar1 + 0xc) + pfVar3[2] * *(float *)(iVar1 + 0x14)) {
      pfVar3[4] = (float)&DAT_803dc0b4;
    }
    else {
      pfVar3[4] = (float)&DAT_803dc0b0;
    }
  }
  return;
}

