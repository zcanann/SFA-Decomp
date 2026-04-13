// Function: FUN_80294d40
// Entry: 80294d40
// Size: 96 bytes

double FUN_80294d40(double param_1)

{
  double dVar1;
  short local_1c [2];
  float local_18;
  
  local_1c[0] = ((ushort)((uint)(float)param_1 >> 0x17) & 0xff) - 0x80;
  local_18 = (float)((uint)(float)param_1 & 0x7fffff | 0x3f800000);
  dVar1 = FUN_80292568((float *)local_1c);
  return (double)(float)((double)local_18 + dVar1);
}

