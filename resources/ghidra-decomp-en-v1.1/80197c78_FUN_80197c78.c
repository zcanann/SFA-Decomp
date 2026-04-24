// Function: FUN_80197c78
// Entry: 80197c78
// Size: 420 bytes

void FUN_80197c78(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0x7f;
  *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0xbf;
  *pfVar3 = FLOAT_803e4d08;
  if ((*(byte *)(param_2 + 0x1a) & 8) != 0) {
    if ((int)*(short *)(param_2 + 0x18) == 0xffffffff) {
      uVar1 = 1;
    }
    else {
      uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18));
      uVar1 = uVar1 & 0xff;
    }
    if (uVar1 != 0) {
      *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0xbf | 0x40;
      *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0x7f | 0x80;
      *pfVar3 = FLOAT_803e4d0c;
      uVar2 = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
      uVar1 = (int)*(short *)(param_2 + 0x20) ^ 0x80000000;
      dVar4 = (double)(*(float *)(param_1 + 0x10) +
                      *pfVar3 * ((float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18) -
                                (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e4d18)) +
                      (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e4d18));
      FUN_8004c38c(dVar4,(double)((float)((double)(float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)(param_2 +
                                                                                          0x1e) ^
                                                                           0x80000000) -
                                                         DOUBLE_803e4d18) + dVar4) -
                                 (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18)),
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(param_2 + 0x24) ^ 0x80000000) -
                                  DOUBLE_803e4d18),
                   (double)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x22) ^ 0x80000000) -
                                   DOUBLE_803e4d18) / FLOAT_803e4d10),(double)FLOAT_803e4d14,
                   *(byte *)(param_2 + 0x1a) & 1);
    }
  }
  return;
}

