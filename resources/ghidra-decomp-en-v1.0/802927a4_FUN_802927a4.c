// Function: FUN_802927a4
// Entry: 802927a4
// Size: 552 bytes

void FUN_802927a4(undefined8 param_1,double param_2)

{
  uint uVar1;
  float fVar2;
  double dVar3;
  float local_4c;
  double local_48;
  
  dVar3 = (double)FUN_80286048();
  fVar2 = (float)dVar3;
  if (fVar2 == FLOAT_803e7ab8) {
    if (param_2 == (double)FLOAT_803e7ab8) {
      dVar3 = (double)FLOAT_803e7bc8;
    }
    else {
      dVar3 = (double)FLOAT_803e7ab8;
    }
  }
  else {
    dVar3 = (double)(float)((uint)fVar2 & 0x7fffff | 0x3f800000) - DOUBLE_803e7ac0;
    dVar3 = param_2 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3
                                                                                               * (
                                                  dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3
                                                                                               * (
                                                  dVar3 * (dVar3 * (dVar3 * (dVar3 * (
                                                  DOUBLE_803e7b60 * dVar3 + DOUBLE_803e7b58) +
                                                  DOUBLE_803e7b50) + DOUBLE_803e7b48) +
                                                  DOUBLE_803e7b40) + DOUBLE_803e7b38) +
                                                  DOUBLE_803e7b30) + DOUBLE_803e7b28) +
                                                  DOUBLE_803e7b20) + DOUBLE_803e7b18) +
                                                  DOUBLE_803e7b10) + DOUBLE_803e7b08) +
                                                  DOUBLE_803e7b00) + DOUBLE_803e7af8) +
                                                  DOUBLE_803e7af0) + DOUBLE_803e7ae8) +
                                                  DOUBLE_803e7ae0) + DOUBLE_803e7ad8) +
                                        DOUBLE_803e7ad0) + DOUBLE_803e7ac8) +
                      ((double)CONCAT44(0x43300000,
                                        (int)(short)(((ushort)((uint)fVar2 >> 0x17) & 0xff) - 0x7f)
                                        ^ 0x80000000) - DOUBLE_803e7bd0));
    uVar1 = (uint)dVar3;
    local_48 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
    dVar3 = dVar3 - (local_48 - DOUBLE_803e7bd0);
    local_4c = FLOAT_803e7bc8;
    if (dVar3 != DOUBLE_803e7b68) {
      local_4c = (float)(dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (
                                                  dVar3 * (DOUBLE_803e7bc0 * dVar3 + DOUBLE_803e7bb8
                                                          ) + DOUBLE_803e7bb0) + DOUBLE_803e7ba8) +
                                                  DOUBLE_803e7ba0) + DOUBLE_803e7b98) +
                                                  DOUBLE_803e7b90) + DOUBLE_803e7b88) +
                                          DOUBLE_803e7b80) + DOUBLE_803e7b78) + DOUBLE_803e7b70);
    }
    if ((((uint)fVar2 & 0x80000000) != 0) && (((int)param_2 & 1U) != 0)) {
      local_4c = -local_4c;
    }
    dVar3 = (double)(float)((int)local_4c + uVar1 * 0x800000);
  }
  FUN_80286094(dVar3);
  return;
}

