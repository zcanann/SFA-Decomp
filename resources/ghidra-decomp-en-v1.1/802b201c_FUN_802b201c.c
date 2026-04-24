// Function: FUN_802b201c
// Entry: 802b201c
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x802b213c) */
/* WARNING: Removing unreachable block (ram,0x802b202c) */

void FUN_802b201c(double param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  
  if (((*(ushort *)(param_3 + 0x6e0) & 0x100) == 0) ||
     (iVar3 = FUN_802aa16c(param_2,param_3), iVar3 == 0)) {
    *(byte *)(param_3 + 0x3f4) = *(byte *)(param_3 + 0x3f4) & 0xdf;
    *(float *)(param_3 + 0x414) = FLOAT_803e8b3c;
  }
  else {
    *(byte *)(param_3 + 0x3f4) = *(byte *)(param_3 + 0x3f4) & 0xdf | 0x20;
    *(float *)(param_3 + 0x414) = (float)((double)*(float *)(param_3 + 0x414) + param_1);
    fVar1 = *(float *)(param_3 + 0x414);
    fVar2 = FLOAT_803e8b3c;
    if ((FLOAT_803e8b3c <= fVar1) && (fVar2 = fVar1, FLOAT_803e8dd4 < fVar1)) {
      fVar2 = FLOAT_803e8dd4;
    }
    *(float *)(param_3 + 0x414) = fVar2;
  }
  *(float *)(param_3 + 0x410) = (float)((double)*(float *)(param_3 + 0x410) - param_1);
  if (*(float *)(param_3 + 0x410) < FLOAT_803e8b3c) {
    *(float *)(param_3 + 0x410) = FLOAT_803e8b3c;
  }
  *(float *)(param_3 + 0x878) = (float)((double)*(float *)(param_3 + 0x878) - param_1);
  if (*(float *)(param_3 + 0x878) < FLOAT_803e8b3c) {
    *(float *)(param_3 + 0x878) = FLOAT_803e8b3c;
  }
  *(float *)(param_3 + 0x87c) = (float)((double)*(float *)(param_3 + 0x87c) - param_1);
  if (*(float *)(param_3 + 0x87c) < FLOAT_803e8b3c) {
    *(float *)(param_3 + 0x87c) = FLOAT_803e8b3c;
  }
  *(float *)(param_3 + 0x880) = (float)((double)*(float *)(param_3 + 0x880) - param_1);
  if (*(float *)(param_3 + 0x880) < FLOAT_803e8b3c) {
    *(float *)(param_3 + 0x880) = FLOAT_803e8b3c;
  }
  return;
}

