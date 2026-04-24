// Function: FUN_80295318
// Entry: 80295318
// Size: 1916 bytes

double FUN_80295318(double param_1,double param_2)

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
  undefined8 local_18;
  undefined8 local_10;
  undefined8 local_8;
  
  fVar1 = (float)param_1;
  dVar6 = (double)fVar1;
  dVar7 = (double)FLOAT_803e8ae8;
  if (dVar7 < dVar6) {
    uVar5 = ((uint)fVar1 >> 0x17) - 0x80;
    uVar4 = ((uint)fVar1 & 0x7fffff) >> 0x10;
    if (((uint)fVar1 & 0xffff) == 0) {
      local_8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      fVar1 = (float)(local_8 - DOUBLE_803e8af8) + FLOAT_803e8aec +
              *(float *)(&DAT_803338d8 + uVar4 * 4);
    }
    else {
      local_2c = (float)((uint)fVar1 & 0x7f0000 | 0x3f800000);
      if (((uint)fVar1 & 0x8000) != 0) {
        uVar4 = uVar4 + 1;
        local_2c = (float)((int)local_2c + 0x10000);
      }
      fVar1 = ((float)((uint)fVar1 & 0x7fffff | 0x3f800000) - local_2c) *
              *(float *)(&DAT_80333688 + uVar4 * 4);
      local_8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      fVar1 = (float)(local_8 - DOUBLE_803e8af8) + FLOAT_803e8aec +
              *(float *)(&DAT_803338d8 + uVar4 * 4) +
              fVar1 + FLOAT_803dd2b8 * fVar1 +
                      fRam803dd2bc * fVar1 + fVar1 * fVar1 * (fVar1 * DAT_803dd2c4 + DAT_803dd2c0);
    }
    uVar4 = (uint)(param_2 * (double)fVar1);
    local_10 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    fVar1 = (float)(param_2 * (double)fVar1) - (float)(local_10 - DOUBLE_803e8af8);
    if ((int)uVar4 < 0x81) {
      if ((int)uVar4 < -0x7f) {
        dVar6 = (double)FLOAT_803e8ae8;
      }
      else {
        dVar6 = (double)((float)((uVar4 + 0x7f) * 0x800000) *
                        (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (
                                                  fVar1 * DAT_80333afc + DAT_80333af8) +
                                                  DAT_80333af4) + DAT_80333af0) + DAT_80333aec) +
                                                  DAT_80333ae8) + DAT_80333ae4) + DAT_80333ae0) +
                                 DAT_80333adc) + FLOAT_803e8af0));
      }
    }
    else {
      dVar6 = (double)DAT_803dd2b4;
    }
  }
  else if (dVar6 < dVar7) {
    uVar4 = (uint)param_2;
    local_18 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    if ((double)(float)(param_2 - (double)(float)(local_18 - DOUBLE_803e8af8)) == dVar7) {
      if (uVar4 == (((int)uVar4 >> 1) + (uint)((int)uVar4 < 0 && (uVar4 & 1) != 0)) * 2) {
        fVar1 = (float)-dVar6;
        uVar5 = ((uint)fVar1 >> 0x17) - 0x80;
        uVar4 = ((uint)fVar1 & 0x7fffff) >> 0x10;
        if (((uint)fVar1 & 0xffff) == 0) {
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e8af8) + FLOAT_803e8aec +
                  *(float *)(&DAT_803338d8 + uVar4 * 4);
        }
        else {
          local_6c = (float)((uint)fVar1 & 0x7f0000 | 0x3f800000);
          if (((uint)fVar1 & 0x8000) != 0) {
            uVar4 = uVar4 + 1;
            local_6c = (float)((int)local_6c + 0x10000);
          }
          fVar1 = ((float)((uint)fVar1 & 0x7fffff | 0x3f800000) - local_6c) *
                  *(float *)(&DAT_80333688 + uVar4 * 4);
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e8af8) + FLOAT_803e8aec +
                  *(float *)(&DAT_803338d8 + uVar4 * 4) +
                  fVar1 + FLOAT_803dd2b8 * fVar1 +
                          fRam803dd2bc * fVar1 +
                          fVar1 * fVar1 * (fVar1 * DAT_803dd2c4 + DAT_803dd2c0);
        }
        uVar4 = (uint)(param_2 * (double)fVar1);
        local_10 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        fVar1 = (float)(param_2 * (double)fVar1) - (float)(local_10 - DOUBLE_803e8af8);
        if ((int)uVar4 < 0x81) {
          if ((int)uVar4 < -0x7f) {
            dVar6 = (double)FLOAT_803e8ae8;
          }
          else {
            dVar6 = (double)((float)((uVar4 + 0x7f) * 0x800000) *
                            (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * 
                                                  (fVar1 * DAT_80333afc + DAT_80333af8) +
                                                  DAT_80333af4) + DAT_80333af0) + DAT_80333aec) +
                                                  DAT_80333ae8) + DAT_80333ae4) + DAT_80333ae0) +
                                     DAT_80333adc) + FLOAT_803e8af0));
          }
        }
        else {
          dVar6 = (double)DAT_803dd2b4;
        }
      }
      else {
        fVar1 = (float)-dVar6;
        uVar5 = ((uint)fVar1 >> 0x17) - 0x80;
        uVar4 = ((uint)fVar1 & 0x7fffff) >> 0x10;
        if (((uint)fVar1 & 0xffff) == 0) {
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e8af8) + FLOAT_803e8aec +
                  *(float *)(&DAT_803338d8 + uVar4 * 4);
        }
        else {
          local_4c = (float)((uint)fVar1 & 0x7f0000 | 0x3f800000);
          if (((uint)fVar1 & 0x8000) != 0) {
            uVar4 = uVar4 + 1;
            local_4c = (float)((int)local_4c + 0x10000);
          }
          fVar1 = ((float)((uint)fVar1 & 0x7fffff | 0x3f800000) - local_4c) *
                  *(float *)(&DAT_80333688 + uVar4 * 4);
          local_18 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          fVar1 = (float)(local_18 - DOUBLE_803e8af8) + FLOAT_803e8aec +
                  *(float *)(&DAT_803338d8 + uVar4 * 4) +
                  fVar1 + FLOAT_803dd2b8 * fVar1 +
                          fRam803dd2bc * fVar1 +
                          fVar1 * fVar1 * (fVar1 * DAT_803dd2c4 + DAT_803dd2c0);
        }
        uVar4 = (uint)(param_2 * (double)fVar1);
        local_10 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        fVar1 = (float)(param_2 * (double)fVar1) - (float)(local_10 - DOUBLE_803e8af8);
        if ((int)uVar4 < 0x81) {
          if ((int)uVar4 < -0x7f) {
            dVar6 = (double)FLOAT_803e8ae8;
          }
          else {
            dVar6 = (double)((float)((uVar4 + 0x7f) * 0x800000) *
                            (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * (fVar1 * 
                                                  (fVar1 * DAT_80333afc + DAT_80333af8) +
                                                  DAT_80333af4) + DAT_80333af0) + DAT_80333aec) +
                                                  DAT_80333ae8) + DAT_80333ae4) + DAT_80333ae0) +
                                     DAT_80333adc) + FLOAT_803e8af0));
          }
        }
        else {
          dVar6 = (double)DAT_803dd2b4;
        }
        dVar6 = -dVar6;
      }
    }
    else {
      dVar6 = (double)DAT_803dd2b0;
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
        dVar6 = (double)FLOAT_803e8af0;
      }
      else {
        if (uVar4 < 3) {
          if (uVar4 != 0) {
            return (double)DAT_803dd2b0;
          }
        }
        else if (uVar4 < 6) {
          if (((uint)fVar1 & 0x80000000) == 0) {
            return dVar6;
          }
          return (double)DAT_803dd2b4;
        }
        dVar6 = (double)FLOAT_803e8ae8;
      }
    }
  }
  return dVar6;
}

