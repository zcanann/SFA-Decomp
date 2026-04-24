// Function: FUN_80294bb8
// Entry: 80294bb8
// Size: 1916 bytes

double FUN_80294bb8(double param_1,double param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  double dVar6;
  double dVar7;
  float local_6c;
  float local_4c;
  float local_2c;
  double local_18;
  double local_10;
  double local_8;
  
  fVar1 = (float)param_1;
  dVar6 = (double)fVar1;
  dVar7 = (double)FLOAT_803e7e50;
  if (dVar7 < dVar6) {
    uVar5 = ((uint)fVar1 >> 0x17) - 0x80;
    uVar4 = ((uint)fVar1 & 0x7fffff) >> 0x10;
    if (((uint)fVar1 & 0xffff) == 0) {
      local_8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      fVar1 = (float)(local_8 - DOUBLE_803e7e60) + FLOAT_803e7e54 +
              *(float *)(&DAT_80332c78 + uVar4 * 4);
    }
    else {
      local_2c = (float)((uint)fVar1 & 0x7f0000 | 0x3f800000);
      if (((uint)fVar1 & 0x8000) != 0) {
        uVar4 = uVar4 + 1;
        local_2c = (float)((int)local_2c + 0x10000);
      }
      fVar1 = ((float)((uint)fVar1 & 0x7fffff | 0x3f800000) - local_2c) *
              *(float *)(&DAT_80332a28 + uVar4 * 4);
      local_8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      fVar1 = (float)(local_8 - DOUBLE_803e7e60) + FLOAT_803e7e54 +
              *(float *)(&DAT_80332c78 + uVar4 * 4) +
              fVar1 + FLOAT_803dc650 * fVar1 +
                      fRam803dc654 * fVar1 + fVar1 * fVar1 * (fVar1 * DAT_803dc65c + DAT_803dc658);
    }
    uVar4 = (uint)(param_2 * (double)fVar1);
    local_10 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    fVar1 = (float)(param_2 * (double)fVar1) - (float)(local_10 - DOUBLE_803e7e60);
    if ((int)uVar4 < 0x81) {
      if ((int)uVar4 < -0x7f) {
        dVar6 = (double)FLOAT_803e7e50;
      }
      else {
        dVar6 = (double)((float)((uVar4 + 0x7f) * 0x800000) *
                        (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (
                                                  fVar1 * DAT_80332e9c + DAT_80332e98) +
                                                  DAT_80332e94) + DAT_80332e90) + DAT_80332e8c) +
                                                  DAT_80332e88) + DAT_80332e84) + DAT_80332e80) +
                                 DAT_80332e7c) + FLOAT_803e7e58));
      }
    }
    else {
      dVar6 = (double)DAT_803dc64c;
    }
  }
  else if (dVar6 < dVar7) {
    uVar4 = (uint)param_2;
    local_18 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    if ((double)(float)(param_2 - (double)(float)(local_18 - DOUBLE_803e7e60)) == dVar7) {
      if (uVar4 == (((int)uVar4 >> 1) + (uint)((int)uVar4 < 0 && (uVar4 & 1) != 0)) * 2) {
        fVar1 = (float)-dVar6;
        uVar5 = ((uint)fVar1 >> 0x17) - 0x80;
        uVar4 = ((uint)fVar1 & 0x7fffff) >> 0x10;
        if (((uint)fVar1 & 0xffff) == 0) {
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e7e60) + FLOAT_803e7e54 +
                  *(float *)(&DAT_80332c78 + uVar4 * 4);
        }
        else {
          local_6c = (float)((uint)fVar1 & 0x7f0000 | 0x3f800000);
          if (((uint)fVar1 & 0x8000) != 0) {
            uVar4 = uVar4 + 1;
            local_6c = (float)((int)local_6c + 0x10000);
          }
          fVar1 = ((float)((uint)fVar1 & 0x7fffff | 0x3f800000) - local_6c) *
                  *(float *)(&DAT_80332a28 + uVar4 * 4);
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e7e60) + FLOAT_803e7e54 +
                  *(float *)(&DAT_80332c78 + uVar4 * 4) +
                  fVar1 + FLOAT_803dc650 * fVar1 +
                          fRam803dc654 * fVar1 +
                          fVar1 * fVar1 * (fVar1 * DAT_803dc65c + DAT_803dc658);
        }
        uVar4 = (uint)(param_2 * (double)fVar1);
        local_10 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        fVar1 = (float)(param_2 * (double)fVar1) - (float)(local_10 - DOUBLE_803e7e60);
        if ((int)uVar4 < 0x81) {
          if ((int)uVar4 < -0x7f) {
            dVar6 = (double)FLOAT_803e7e50;
          }
          else {
            dVar6 = (double)((float)((uVar4 + 0x7f) * 0x800000) *
                            (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * 
                                                  (fVar1 * DAT_80332e9c + DAT_80332e98) +
                                                  DAT_80332e94) + DAT_80332e90) + DAT_80332e8c) +
                                                  DAT_80332e88) + DAT_80332e84) + DAT_80332e80) +
                                     DAT_80332e7c) + FLOAT_803e7e58));
          }
        }
        else {
          dVar6 = (double)DAT_803dc64c;
        }
      }
      else {
        fVar1 = (float)-dVar6;
        uVar5 = ((uint)fVar1 >> 0x17) - 0x80;
        uVar4 = ((uint)fVar1 & 0x7fffff) >> 0x10;
        if (((uint)fVar1 & 0xffff) == 0) {
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e7e60) + FLOAT_803e7e54 +
                  *(float *)(&DAT_80332c78 + uVar4 * 4);
        }
        else {
          local_4c = (float)((uint)fVar1 & 0x7f0000 | 0x3f800000);
          if (((uint)fVar1 & 0x8000) != 0) {
            uVar4 = uVar4 + 1;
            local_4c = (float)((int)local_4c + 0x10000);
          }
          fVar1 = ((float)((uint)fVar1 & 0x7fffff | 0x3f800000) - local_4c) *
                  *(float *)(&DAT_80332a28 + uVar4 * 4);
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e7e60) + FLOAT_803e7e54 +
                  *(float *)(&DAT_80332c78 + uVar4 * 4) +
                  fVar1 + FLOAT_803dc650 * fVar1 +
                          fRam803dc654 * fVar1 +
                          fVar1 * fVar1 * (fVar1 * DAT_803dc65c + DAT_803dc658);
        }
        uVar4 = (uint)(param_2 * (double)fVar1);
        local_10 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        fVar1 = (float)(param_2 * (double)fVar1) - (float)(local_10 - DOUBLE_803e7e60);
        if ((int)uVar4 < 0x81) {
          if ((int)uVar4 < -0x7f) {
            dVar6 = (double)FLOAT_803e7e50;
          }
          else {
            dVar6 = (double)((float)((uVar4 + 0x7f) * 0x800000) *
                            (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * 
                                                  (fVar1 * DAT_80332e9c + DAT_80332e98) +
                                                  DAT_80332e94) + DAT_80332e90) + DAT_80332e8c) +
                                                  DAT_80332e88) + DAT_80332e84) + DAT_80332e80) +
                                     DAT_80332e7c) + FLOAT_803e7e58));
          }
        }
        else {
          dVar6 = (double)DAT_803dc64c;
        }
        dVar6 = -dVar6;
      }
    }
    else {
      dVar6 = (double)DAT_803dc648;
    }
  }
  else {
    uVar4 = (uint)fVar1 & 0x7f800000;
    if (uVar4 == 0x7f800000) {
      if (((uint)fVar1 & 0x7fffff) == 0) {
        iVar3 = 2;
      }
      else {
        iVar3 = 1;
      }
    }
    else if ((uVar4 < 0x7f800000) && (uVar4 == 0)) {
      if (((uint)fVar1 & 0x7fffff) == 0) {
        iVar3 = 3;
      }
      else {
        iVar3 = 5;
      }
    }
    else {
      iVar3 = 4;
    }
    if (iVar3 != 1) {
      fVar2 = (float)param_2;
      uVar4 = (uint)fVar2 & 0x7f800000;
      if (uVar4 == 0x7f800000) {
        if (((uint)fVar2 & 0x7fffff) == 0) {
          uVar4 = 2;
        }
        else {
          uVar4 = 1;
        }
      }
      else if ((uVar4 < 0x7f800000) && (uVar4 == 0)) {
        if (((uint)fVar2 & 0x7fffff) == 0) {
          uVar4 = 3;
        }
        else {
          uVar4 = 5;
        }
      }
      else {
        uVar4 = 4;
      }
      if (uVar4 == 3) {
        dVar6 = (double)FLOAT_803e7e58;
      }
      else {
        if (uVar4 < 3) {
          if (uVar4 != 0) {
            return (double)DAT_803dc648;
          }
        }
        else if (uVar4 < 6) {
          if (((uint)fVar1 & 0x80000000) == 0) {
            return dVar6;
          }
          return (double)DAT_803dc64c;
        }
        dVar6 = (double)FLOAT_803e7e50;
      }
    }
  }
  return dVar6;
}

