// Function: FUN_8018bcbc
// Entry: 8018bcbc
// Size: 768 bytes

void FUN_8018bcbc(int param_1)

{
  float fVar1;
  char cVar4;
  int iVar2;
  int iVar3;
  float *pfVar5;
  int iVar6;
  double dVar7;
  double local_18;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  pfVar5 = *(float **)(param_1 + 0xb8);
  if (*(short *)(iVar6 + 0x1a) == -1) {
    cVar4 = '\x01';
  }
  else {
    cVar4 = FUN_8001ffb4();
  }
  if (cVar4 != '\0') {
    if (-1 < (char)*(byte *)(pfVar5 + 3)) {
      if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
        FUN_8004c210((double)(FLOAT_803e3c90 + *(float *)(param_1 + 0x1c)),
                     (double)(*(float *)(param_1 + 0x1c) - FLOAT_803e3c94),(double)FLOAT_803e3c98,
                     (double)FLOAT_803e3c9c,(double)FLOAT_803e3ca0,0);
      }
      *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f | 0x80;
    }
    iVar2 = FUN_8002b9ec();
    iVar3 = FUN_80295cd4();
    if (((iVar3 != 0) || (FLOAT_803e3ca4 + *(float *)(param_1 + 0x1c) < *(float *)(iVar2 + 0x1c)))
       || (dVar7 = (double)FUN_80021704(iVar2 + 0x18,param_1 + 0x18), (double)pfVar5[2] < dVar7)) {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x19));
        *pfVar5 = *pfVar5 + (FLOAT_803db414 * (float)(local_18 - DOUBLE_803e3cb8)) / FLOAT_803e3cac;
        if (FLOAT_803e3ca8 < *pfVar5) {
          (**(code **)(*DAT_803dca68 + 100))();
          *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
        }
      }
    }
    else {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
        (**(code **)(*DAT_803dca68 + 0x58))(6000,0x603);
        *pfVar5 = FLOAT_803e3ca8;
        *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf | 0x40;
      }
      local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x18));
      *pfVar5 = *pfVar5 - (FLOAT_803db414 * (float)(local_18 - DOUBLE_803e3cb8)) / FLOAT_803e3cac;
      fVar1 = FLOAT_803e3cb0;
      if (*pfVar5 <= FLOAT_803e3cb0) {
        *pfVar5 = FLOAT_803e3cb0;
        pfVar5[1] = pfVar5[1] - FLOAT_803db414;
        if (pfVar5[1] < fVar1) {
          pfVar5[1] = pfVar5[1] + FLOAT_803e3cb4;
          FUN_80036450(iVar2,param_1,0x16,1,0);
        }
      }
    }
    if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
      (**(code **)(*DAT_803dca68 + 0x5c))((int)*pfVar5);
    }
    return;
  }
  if ((char)*(byte *)(pfVar5 + 3) < '\0') {
    if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
      FUN_8004c204();
    }
    *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f;
  }
  if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
    return;
  }
  (**(code **)(*DAT_803dca68 + 0x60))();
  *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
  return;
}

