// Function: FUN_8018c238
// Entry: 8018c238
// Size: 768 bytes

void FUN_8018c238(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  undefined8 local_18;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  pfVar5 = *(float **)(param_1 + 0xb8);
  if ((int)*(short *)(iVar6 + 0x1a) == 0xffffffff) {
    uVar2 = 1;
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar6 + 0x1a));
    uVar2 = uVar2 & 0xff;
  }
  if (uVar2 != 0) {
    if (-1 < (char)*(byte *)(pfVar5 + 3)) {
      if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
        FUN_8004c38c((double)(FLOAT_803e4928 + *(float *)(param_1 + 0x1c)),
                     (double)(*(float *)(param_1 + 0x1c) - FLOAT_803e492c),(double)FLOAT_803e4930,
                     (double)FLOAT_803e4934,(double)FLOAT_803e4938,0);
      }
      *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f | 0x80;
    }
    iVar3 = FUN_8002bac4();
    bVar4 = FUN_80296434(iVar3);
    if (((bVar4 != 0) || (FLOAT_803e493c + *(float *)(param_1 + 0x1c) < *(float *)(iVar3 + 0x1c)))
       || (dVar7 = (double)FUN_800217c8((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18)),
          (double)pfVar5[2] < dVar7)) {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x19));
        *pfVar5 = *pfVar5 + (FLOAT_803dc074 * (float)(local_18 - DOUBLE_803e4950)) / FLOAT_803e4944;
        if (FLOAT_803e4940 < *pfVar5) {
          (**(code **)(*DAT_803dd6e8 + 100))();
          *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
        }
      }
    }
    else {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
        (**(code **)(*DAT_803dd6e8 + 0x58))(6000,0x603);
        *pfVar5 = FLOAT_803e4940;
        *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf | 0x40;
      }
      local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x18));
      *pfVar5 = *pfVar5 - (FLOAT_803dc074 * (float)(local_18 - DOUBLE_803e4950)) / FLOAT_803e4944;
      fVar1 = FLOAT_803e4948;
      if (*pfVar5 <= FLOAT_803e4948) {
        *pfVar5 = FLOAT_803e4948;
        pfVar5[1] = pfVar5[1] - FLOAT_803dc074;
        if (pfVar5[1] < fVar1) {
          pfVar5[1] = pfVar5[1] + FLOAT_803e494c;
          FUN_80036548(iVar3,param_1,'\x16',1,0);
        }
      }
    }
    if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
      (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*pfVar5);
    }
    return;
  }
  if ((char)*(byte *)(pfVar5 + 3) < '\0') {
    if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
      FUN_8004c380();
    }
    *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f;
  }
  if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
    return;
  }
  (**(code **)(*DAT_803dd6e8 + 0x60))();
  *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
  return;
}

