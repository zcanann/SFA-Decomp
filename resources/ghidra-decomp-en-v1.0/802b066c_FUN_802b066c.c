// Function: FUN_802b066c
// Entry: 802b066c
// Size: 364 bytes

void FUN_802b066c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  float local_1c;
  float local_18;
  float local_14 [3];
  
  if (*(char *)(param_2 + 0x86c) != '\x1a') {
    if ((*(byte *)(param_2 + 0x3f0) >> 4 & 1) == 0) {
      dVar4 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c)
                                           + *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24)
                                             + *(float *)(param_1 + 0x28) *
                                               *(float *)(param_1 + 0x28)));
      *(float *)(param_2 + 0x7a4) = (float)dVar4;
      fVar1 = *(float *)(param_2 + 0x7a4);
      fVar2 = FLOAT_803e7ee0;
      if ((FLOAT_803e7ee0 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8138 < fVar1)) {
        fVar2 = FLOAT_803e8138;
      }
      *(float *)(param_2 + 0x7a4) = fVar2;
    }
    *(float *)(param_2 + 0x79c) =
         -(FLOAT_803db414 * *(float *)(param_2 + 0x7a4) - *(float *)(param_2 + 0x79c));
    fVar1 = FLOAT_803e7ea4;
    if (FLOAT_803e7ea4 < *(float *)(param_2 + 0x79c)) {
      *(float *)(param_2 + 0x7a0) = *(float *)(param_2 + 0x7a0) - FLOAT_803db414;
      if (*(float *)(param_2 + 0x7a0) <= fVar1) {
        FUN_8003842c(param_1,0xb,&local_1c,&local_18,local_14,0);
        FUN_800365b8((double)local_1c,(double)local_18,(double)local_14[0],param_1,0,0x1f,1,
                     0xffffffff);
        *(float *)(param_2 + 0x7a0) = FLOAT_803e8050;
      }
    }
    else {
      iVar3 = FUN_8000b5d0(param_1,0x394);
      if (iVar3 != 0) {
        FUN_8000b824(param_1,0x394);
        FUN_8000bb18(param_1,0x395);
      }
      *(float *)(param_2 + 0x79c) = FLOAT_803e7ea4;
    }
  }
  return;
}

