// Function: FUN_801979f0
// Entry: 801979f0
// Size: 648 bytes

void FUN_801979f0(int param_1)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pfVar4 = *(float **)(param_1 + 0xb8);
  if ((int)*(short *)(iVar5 + 0x18) == 0xffffffff) {
    uVar2 = 1;
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar5 + 0x18));
    uVar2 = uVar2 & 0xff;
  }
  if (((uVar2 == 0) || ((*(byte *)(pfVar4 + 1) >> 6 & 1) != 0)) &&
     ((uVar2 != 0 || (-1 < *(char *)(pfVar4 + 1))))) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if (bVar1) {
    if (uVar2 == 0) {
      if ((*(byte *)(iVar5 + 0x1a) & 4) == 0) {
        *pfVar4 = -(FLOAT_803e4d04 * FLOAT_803dc074 - *pfVar4);
      }
      else {
        *pfVar4 = -(FLOAT_803e4d00 * FLOAT_803dc074 - *pfVar4);
      }
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xbf;
    }
    else {
      if ((*(byte *)(iVar5 + 0x1a) & 2) == 0) {
        *pfVar4 = FLOAT_803e4d04 * FLOAT_803dc074 + *pfVar4;
      }
      else {
        *pfVar4 = FLOAT_803e4d00 * FLOAT_803dc074 + *pfVar4;
      }
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f | 0x80;
    }
    if (FLOAT_803e4d08 < *pfVar4) {
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f | 0x80;
      if (FLOAT_803e4d0c < *pfVar4) {
        *pfVar4 = FLOAT_803e4d0c;
        *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xbf | 0x40;
      }
      uVar3 = (int)*(short *)(iVar5 + 0x1c) ^ 0x80000000;
      uVar2 = (int)*(short *)(iVar5 + 0x20) ^ 0x80000000;
      dVar6 = (double)(*(float *)(param_1 + 0x10) +
                      *pfVar4 * ((float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4d18) -
                                (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18)) +
                      (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18));
      FUN_8004c38c(dVar6,(double)((float)((double)(float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)(iVar5 + 
                                                  0x1e) ^ 0x80000000) - DOUBLE_803e4d18) + dVar6) -
                                 (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4d18)),
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar5 + 0x24) ^ 0x80000000) -
                                  DOUBLE_803e4d18),
                   (double)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar5 + 0x22) ^ 0x80000000) -
                                   DOUBLE_803e4d18) / FLOAT_803e4d10),(double)FLOAT_803e4d14,
                   *(byte *)(iVar5 + 0x1a) & 1);
    }
    else {
      *pfVar4 = FLOAT_803e4d08;
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f;
      FUN_8004c380();
    }
  }
  return;
}

