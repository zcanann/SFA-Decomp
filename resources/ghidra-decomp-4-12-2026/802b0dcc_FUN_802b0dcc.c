// Function: FUN_802b0dcc
// Entry: 802b0dcc
// Size: 364 bytes

void FUN_802b0dcc(uint param_1,int param_2)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  double dVar4;
  float local_1c;
  float local_18;
  float local_14 [3];
  
  if (*(char *)(param_2 + 0x86c) != '\x1a') {
    if ((*(byte *)(param_2 + 0x3f0) >> 4 & 1) == 0) {
      dVar4 = FUN_80293900((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                                   *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                                   *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
      *(float *)(param_2 + 0x7a4) = (float)dVar4;
      fVar1 = *(float *)(param_2 + 0x7a4);
      fVar2 = FLOAT_803e8b78;
      if ((FLOAT_803e8b78 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8dd0 < fVar1)) {
        fVar2 = FLOAT_803e8dd0;
      }
      *(float *)(param_2 + 0x7a4) = fVar2;
    }
    *(float *)(param_2 + 0x79c) =
         -(FLOAT_803dc074 * *(float *)(param_2 + 0x7a4) - *(float *)(param_2 + 0x79c));
    fVar1 = FLOAT_803e8b3c;
    if (FLOAT_803e8b3c < *(float *)(param_2 + 0x79c)) {
      *(float *)(param_2 + 0x7a0) = *(float *)(param_2 + 0x7a0) - FLOAT_803dc074;
      if (*(float *)(param_2 + 0x7a0) <= fVar1) {
        FUN_80038524(param_1,0xb,&local_1c,&local_18,local_14,0);
        FUN_800366b0((double)local_1c,(double)local_18,(double)local_14[0],param_1,0,'\x1f',1,0xff);
        *(float *)(param_2 + 0x7a0) = FLOAT_803e8ce8;
      }
    }
    else {
      bVar3 = FUN_8000b5f0(param_1,0x394);
      if (bVar3) {
        FUN_8000b844(param_1,0x394);
        FUN_8000bb38(param_1,0x395);
      }
      *(float *)(param_2 + 0x79c) = FLOAT_803e8b3c;
    }
  }
  return;
}

