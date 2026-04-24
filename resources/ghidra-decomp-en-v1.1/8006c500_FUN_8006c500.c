// Function: FUN_8006c500
// Entry: 8006c500
// Size: 316 bytes

void FUN_8006c500(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  
  if (DAT_803ddbf8 < 300) {
    (&DAT_8038ef08)[(uint)DAT_803ddbf8 * 3] = param_1;
    fVar1 = *(float *)(param_1 + 0x18) - *(float *)(DAT_803ddc68 + 0xc);
    fVar2 = *(float *)(param_1 + 0x1c) - *(float *)(DAT_803ddc68 + 0x10);
    fVar3 = *(float *)(param_1 + 0x20) - *(float *)(DAT_803ddc68 + 0x14);
    dVar6 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2);
    if ((double)FLOAT_803df9a8 < dVar6) {
      dVar5 = 1.0 / SQRT(dVar6);
      dVar5 = DOUBLE_803df9d8 * dVar5 * -(dVar6 * dVar5 * dVar5 - DOUBLE_803df9e0);
      dVar5 = DOUBLE_803df9d8 * dVar5 * -(dVar6 * dVar5 * dVar5 - DOUBLE_803df9e0);
      dVar6 = (double)(float)(dVar6 * DOUBLE_803df9d8 * dVar5 *
                                      -(dVar6 * dVar5 * dVar5 - DOUBLE_803df9e0));
    }
    iVar4 = (uint)DAT_803ddbf8 * 0xc;
    *(float *)(&DAT_8038ef0c + iVar4) = (float)((double)**(float **)(param_1 + 100) / dVar6);
    if (*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 2) {
      (&DAT_8038ef10)[iVar4] = 1;
      if ((*(byte *)(*(int *)(param_1 + 0x50) + 0x5f) & 4) != 0) {
        (&DAT_8038ef10)[iVar4] = 2;
        *(float *)(&DAT_8038ef0c + iVar4) = FLOAT_803dfa10;
      }
    }
    else {
      (&DAT_8038ef10)[iVar4] = 0;
    }
    DAT_803ddbf8 = DAT_803ddbf8 + 1;
  }
  return;
}

