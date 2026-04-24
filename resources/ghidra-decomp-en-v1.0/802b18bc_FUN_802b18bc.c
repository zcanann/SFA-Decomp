// Function: FUN_802b18bc
// Entry: 802b18bc
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x802b19dc) */

void FUN_802b18bc(double param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (((*(ushort *)(param_3 + 0x6e0) & 0x100) == 0) || (iVar3 = FUN_802a9a0c(), iVar3 == 0)) {
    *(byte *)(param_3 + 0x3f4) = *(byte *)(param_3 + 0x3f4) & 0xdf;
    *(float *)(param_3 + 0x414) = FLOAT_803e7ea4;
  }
  else {
    *(byte *)(param_3 + 0x3f4) = *(byte *)(param_3 + 0x3f4) & 0xdf | 0x20;
    *(float *)(param_3 + 0x414) = (float)((double)*(float *)(param_3 + 0x414) + param_1);
    fVar1 = *(float *)(param_3 + 0x414);
    fVar2 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e813c < fVar1)) {
      fVar2 = FLOAT_803e813c;
    }
    *(float *)(param_3 + 0x414) = fVar2;
  }
  *(float *)(param_3 + 0x410) = (float)((double)*(float *)(param_3 + 0x410) - param_1);
  if (*(float *)(param_3 + 0x410) < FLOAT_803e7ea4) {
    *(float *)(param_3 + 0x410) = FLOAT_803e7ea4;
  }
  *(float *)(param_3 + 0x878) = (float)((double)*(float *)(param_3 + 0x878) - param_1);
  if (*(float *)(param_3 + 0x878) < FLOAT_803e7ea4) {
    *(float *)(param_3 + 0x878) = FLOAT_803e7ea4;
  }
  *(float *)(param_3 + 0x87c) = (float)((double)*(float *)(param_3 + 0x87c) - param_1);
  if (*(float *)(param_3 + 0x87c) < FLOAT_803e7ea4) {
    *(float *)(param_3 + 0x87c) = FLOAT_803e7ea4;
  }
  *(float *)(param_3 + 0x880) = (float)((double)*(float *)(param_3 + 0x880) - param_1);
  if (*(float *)(param_3 + 0x880) < FLOAT_803e7ea4) {
    *(float *)(param_3 + 0x880) = FLOAT_803e7ea4;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

