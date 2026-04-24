// Function: FUN_802945e0
// Entry: 802945e0
// Size: 96 bytes

double FUN_802945e0(double param_1)

{
  double dVar1;
  short local_1c [2];
  float local_18;
  
  local_1c[0] = ((ushort)((uint)(float)param_1 >> 0x17) & 0xff) - 0x80;
  local_18 = (float)((uint)(float)param_1 & 0x7fffff | 0x3f800000);
  dVar1 = (double)FUN_80291e08(local_1c);
  return (double)(float)((double)local_18 + dVar1);
}

