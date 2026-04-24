// Function: FUN_80292b44
// Entry: 80292b44
// Size: 236 bytes

void FUN_80292b44(undefined8 param_1,double param_2)

{
  float fVar1;
  double dVar2;
  short local_30 [2];
  float local_2c;
  float local_28;
  longlong local_20;
  
  dVar2 = (double)FUN_80286050();
  fVar1 = (float)dVar2;
  if (fVar1 == FLOAT_803e7ab8) {
    if (param_2 == (double)FLOAT_803e7ab8) {
      dVar2 = (double)FLOAT_803e7bc8;
    }
    else {
      dVar2 = (double)FLOAT_803e7ab8;
    }
  }
  else {
    local_30[0] = ((ushort)((uint)fVar1 >> 0x17) & 0xff) - 0x80;
    local_2c = (float)((uint)fVar1 & 0x7fffff | 0x3f800000);
    dVar2 = (double)FUN_80291e08(local_30);
    local_2c = (float)((double)FLOAT_803e7bf4 * param_2) * (float)((double)local_2c + dVar2);
    local_20 = (longlong)(int)local_2c;
    local_28 = (float)((int)local_2c + 0x3f800000);
    if ((((uint)fVar1 & 0x80000000) != 0) &&
       (local_20 = (longlong)(int)param_2, ((int)param_2 & 1U) != 0)) {
      local_28 = (float)((uint)local_28 ^ 0x80000000);
    }
    dVar2 = (double)local_28;
  }
  FUN_8028609c(dVar2);
  return;
}

