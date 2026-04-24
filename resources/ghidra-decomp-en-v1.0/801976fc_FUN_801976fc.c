// Function: FUN_801976fc
// Entry: 801976fc
// Size: 420 bytes

void FUN_801976fc(int param_1,int param_2)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f;
  *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xbf;
  *pfVar4 = FLOAT_803e4070;
  if ((*(byte *)(param_2 + 0x1a) & 8) != 0) {
    if (*(short *)(param_2 + 0x18) == -1) {
      cVar2 = '\x01';
    }
    else {
      cVar2 = FUN_8001ffb4();
    }
    if (cVar2 != '\0') {
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xbf | 0x40;
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f | 0x80;
      *pfVar4 = FLOAT_803e4074;
      uVar3 = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
      uVar1 = (int)*(short *)(param_2 + 0x20) ^ 0x80000000;
      dVar5 = (double)(*(float *)(param_1 + 0x10) +
                      *pfVar4 * ((float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4080) -
                                (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e4080)) +
                      (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e4080));
      FUN_8004c210(dVar5,(double)((float)((double)(float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)(param_2 +
                                                                                          0x1e) ^
                                                                           0x80000000) -
                                                         DOUBLE_803e4080) + dVar5) -
                                 (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4080)),
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(param_2 + 0x24) ^ 0x80000000) -
                                  DOUBLE_803e4080),
                   (double)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x22) ^ 0x80000000) -
                                   DOUBLE_803e4080) / FLOAT_803e4078),(double)FLOAT_803e407c,
                   *(byte *)(param_2 + 0x1a) & 1);
    }
  }
  return;
}

