// Function: FUN_802949e4
// Entry: 802949e4
// Size: 420 bytes

double FUN_802949e4(double param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  double local_18;
  
  fVar1 = (float)param_1;
  if (((uint)fVar1 & 0x80000000) == 0) {
    fVar2 = FLOAT_803e7e3c + FLOAT_803e7e38 * fVar1;
  }
  else {
    fVar2 = FLOAT_803e7e38 * fVar1 - FLOAT_803e7e3c;
  }
  uVar4 = (uint)fVar2;
  uVar3 = uVar4 & 3;
  local_18 = (double)CONCAT44(0x43300000,uVar4 << 1 ^ 0x80000000);
  dVar6 = (double)(DAT_80332a24 * fVar1 +
                  DAT_80332a20 * fVar1 +
                  DAT_80332a1c * fVar1 +
                  DAT_80332a18 * fVar1 + (fVar1 - (float)(local_18 - DOUBLE_803e7e48)));
  dVar5 = (double)FUN_8029471c(dVar6);
  if ((double)FLOAT_803e7e40 <= dVar5) {
    fVar1 = (float)(dVar6 * dVar6);
    if ((uVar4 & 1) == 0) {
      dVar5 = (double)((float)(dVar6 * (double)(fVar1 * (fVar1 * (fVar1 * (DAT_80332c50 * fVar1 +
                                                                          DAT_80332c58) +
                                                                 DAT_80332c60) + DAT_80332c68) +
                                               DAT_80332c70)) *
                      *(float *)(&DAT_80332c30 + uVar3 * 8));
    }
    else {
      dVar5 = (double)((fVar1 * (fVar1 * (fVar1 * (DAT_80332c4c * fVar1 + DAT_80332c54) +
                                         DAT_80332c5c) + DAT_80332c64) + DAT_80332c6c) *
                      *(float *)(&DAT_80332c2c + uVar3 * 8));
    }
  }
  else {
    dVar5 = (double)(DAT_80332c70 * (float)(dVar6 * (double)*(float *)(&DAT_80332c30 + uVar3 * 8)) +
                    *(float *)(&DAT_80332c2c + uVar3 * 8));
  }
  return dVar5;
}

