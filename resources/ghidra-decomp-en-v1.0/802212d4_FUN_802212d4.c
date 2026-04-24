// Function: FUN_802212d4
// Entry: 802212d4
// Size: 340 bytes

void FUN_802212d4(short *param_1,int param_2)

{
  int iVar1;
  float *pfVar2;
  double dVar3;
  
  FUN_80037200(param_1,0x13);
  FUN_80037200(param_1,0x39);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar2 = *(float **)(param_1 + 0x5c);
  dVar3 = (double)FUN_80293e80((double)((FLOAT_803e6bf0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e6c00)) / FLOAT_803e6bf4));
  *pfVar2 = (float)dVar3;
  pfVar2[1] = FLOAT_803e6bf8;
  dVar3 = (double)FUN_80294204((double)((FLOAT_803e6bf0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e6c00)) / FLOAT_803e6bf4));
  pfVar2[2] = (float)dVar3;
  pfVar2[3] = -(pfVar2[2] * *(float *)(param_1 + 10) +
               *pfVar2 * *(float *)(param_1 + 6) + pfVar2[1] * *(float *)(param_1 + 8));
  param_1[0x58] = param_1[0x58] | 0xe000;
  iVar1 = FUN_8001ffb4(0x7a9);
  if (*(char *)(param_2 + 0x19) == iVar1) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0x56),0xc,1);
  }
  return;
}

