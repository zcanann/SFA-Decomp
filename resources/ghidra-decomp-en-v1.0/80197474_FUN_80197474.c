// Function: FUN_80197474
// Entry: 80197474
// Size: 648 bytes

void FUN_80197474(int param_1)

{
  bool bVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  pfVar5 = *(float **)(param_1 + 0xb8);
  if (*(short *)(iVar6 + 0x18) == -1) {
    cVar3 = '\x01';
  }
  else {
    cVar3 = FUN_8001ffb4();
  }
  if (((cVar3 == '\0') || ((*(byte *)(pfVar5 + 1) >> 6 & 1) != 0)) &&
     ((cVar3 != '\0' || (-1 < *(char *)(pfVar5 + 1))))) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if (bVar1) {
    if (cVar3 == '\0') {
      if ((*(byte *)(iVar6 + 0x1a) & 4) == 0) {
        *pfVar5 = -(FLOAT_803e406c * FLOAT_803db414 - *pfVar5);
      }
      else {
        *pfVar5 = -(FLOAT_803e4068 * FLOAT_803db414 - *pfVar5);
      }
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0xbf;
    }
    else {
      if ((*(byte *)(iVar6 + 0x1a) & 2) == 0) {
        *pfVar5 = FLOAT_803e406c * FLOAT_803db414 + *pfVar5;
      }
      else {
        *pfVar5 = FLOAT_803e4068 * FLOAT_803db414 + *pfVar5;
      }
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0x7f | 0x80;
    }
    if (FLOAT_803e4070 < *pfVar5) {
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0x7f | 0x80;
      if (FLOAT_803e4074 < *pfVar5) {
        *pfVar5 = FLOAT_803e4074;
        *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0xbf | 0x40;
      }
      uVar4 = (int)*(short *)(iVar6 + 0x1c) ^ 0x80000000;
      uVar2 = (int)*(short *)(iVar6 + 0x20) ^ 0x80000000;
      dVar7 = (double)(*(float *)(param_1 + 0x10) +
                      *pfVar5 * ((float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e4080) -
                                (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4080)) +
                      (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4080));
      FUN_8004c210(dVar7,(double)((float)((double)(float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)(iVar6 + 
                                                  0x1e) ^ 0x80000000) - DOUBLE_803e4080) + dVar7) -
                                 (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e4080)),
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar6 + 0x24) ^ 0x80000000) -
                                  DOUBLE_803e4080),
                   (double)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar6 + 0x22) ^ 0x80000000) -
                                   DOUBLE_803e4080) / FLOAT_803e4078),(double)FLOAT_803e407c,
                   *(byte *)(iVar6 + 0x1a) & 1);
    }
    else {
      *pfVar5 = FLOAT_803e4070;
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0x7f;
      FUN_8004c204();
    }
  }
  return;
}

