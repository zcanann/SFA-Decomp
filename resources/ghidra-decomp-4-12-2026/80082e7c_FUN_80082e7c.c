// Function: FUN_80082e7c
// Entry: 80082e7c
// Size: 652 bytes

double FUN_80082e7c(undefined8 param_1,undefined8 param_2,double param_3,float *param_4,int param_5,
                   int param_6)

{
  float fVar1;
  byte bVar2;
  int iVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  undefined4 local_8;
  uint uStack_4;
  
  if (param_5 < 1) {
    dVar6 = (double)FLOAT_803dfc30;
  }
  else {
    iVar3 = 0;
    for (pfVar4 = param_4; (iVar3 < param_5 && (*(short *)((int)pfVar4 + 6) < param_6));
        pfVar4 = pfVar4 + 2) {
      iVar3 = iVar3 + 1;
    }
    if (iVar3 == param_5) {
      dVar6 = (double)param_4[param_5 * 2 + -2];
    }
    else if (iVar3 == 0) {
      dVar6 = (double)*param_4;
    }
    else if (param_6 == *(short *)((int)param_4 + iVar3 * 8 + 6)) {
      dVar6 = (double)param_4[iVar3 * 2];
      if ((1 < (*(byte *)(param_4 + iVar3 * 2 + 1) & 3)) && (iVar3 < param_5 + -1)) {
        dVar6 = (double)param_4[iVar3 * 2 + 2];
      }
    }
    else {
      iVar5 = iVar3 + -1;
      pfVar4 = param_4 + iVar5 * 2;
      bVar2 = *(byte *)(pfVar4 + 1) & 3;
      local_18 = *pfVar4;
      if (bVar2 == 0) {
        param_3 = (double)(pfVar4[2] - local_18);
        dVar6 = param_3;
        if (0 < iVar5) {
          dVar6 = (double)(local_18 - pfVar4[-2]);
        }
        if (param_3 < (double)FLOAT_803dfc30) {
          param_3 = -param_3;
        }
        if (dVar6 < (double)FLOAT_803dfc30) {
          dVar6 = -dVar6;
        }
        local_10 = (float)(param_3 + dVar6) * FLOAT_803dfc80 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(pfVar4 + 1) >> 2 ^ 0x80000000)
                          - DOUBLE_803dfc38);
      }
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)((int)param_4 + iVar5 * 8 + 0xe) -
                                       (int)*(short *)((int)param_4 + iVar5 * 8 + 6) ^ 0x80000000) -
                     DOUBLE_803dfc38);
      if (iVar3 < param_5) {
        local_14 = param_4[iVar3 * 2];
        if (bVar2 == 0) {
          dVar6 = param_3;
          if (iVar3 + 1 < param_5) {
            dVar6 = (double)((param_4 + iVar3 * 2)[2] - local_14);
          }
          if (dVar6 < (double)FLOAT_803dfc30) {
            dVar6 = -dVar6;
          }
          local_c = (float)(param_3 + dVar6) * FLOAT_803dfc80 *
                    (float)((double)CONCAT44(0x43300000,
                                             (int)*(char *)(param_4 + iVar3 * 2 + 1) >> 2 ^
                                             0x80000000) - DOUBLE_803dfc38);
        }
      }
      if (fVar1 <= FLOAT_803dfc30) {
        dVar6 = (double)local_14;
      }
      else {
        uStack_4 = param_6 - *(short *)((int)param_4 + iVar3 * 8 + -2) ^ 0x80000000;
        local_8 = 0x43300000;
        dVar6 = (double)((float)((double)CONCAT44(0x43300000,uStack_4) - DOUBLE_803dfc38) / fVar1);
        if (bVar2 == 0) {
          dVar6 = FUN_80010de0(dVar6,&local_18,(float *)0x0);
        }
        else if (bVar2 == 1) {
          dVar6 = (double)(float)(dVar6 * (double)(float)((double)local_14 - (double)local_18) +
                                 (double)local_18);
        }
        else {
          dVar6 = (double)local_14;
        }
      }
    }
  }
  return dVar6;
}

