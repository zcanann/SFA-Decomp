// Function: FUN_802932a4
// Entry: 802932a4
// Size: 236 bytes

void FUN_802932a4(undefined8 param_1,double param_2)

{
  float fVar1;
  double dVar2;
  short local_30 [2];
  float local_2c;
  uint local_28;
  longlong local_20;
  
  dVar2 = (double)FUN_802867b4();
  fVar1 = (float)dVar2;
  if (fVar1 != FLOAT_803e8750) {
    local_30[0] = ((ushort)((uint)fVar1 >> 0x17) & 0xff) - 0x80;
    local_2c = (float)((uint)fVar1 & 0x7fffff | 0x3f800000);
    dVar2 = FUN_80292568((float *)local_30);
    local_2c = (float)((double)FLOAT_803e888c * param_2) * (float)((double)local_2c + dVar2);
    local_20 = (longlong)(int)local_2c;
    local_28 = (int)local_2c + 0x3f800000;
    if ((((uint)fVar1 & 0x80000000) != 0) &&
       (local_20 = (longlong)(int)param_2, ((int)param_2 & 1U) != 0)) {
      local_28 = local_28 ^ 0x80000000;
    }
  }
  FUN_80286800();
  return;
}

