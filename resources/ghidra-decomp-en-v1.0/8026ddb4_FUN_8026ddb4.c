// Function: FUN_8026ddb4
// Entry: 8026ddb4
// Size: 164 bytes

byte * FUN_8026ddb4(byte *param_1,ushort *param_2,short *param_3)

{
  byte bVar1;
  
  bVar1 = *param_1;
  if ((bVar1 == 0x80) && (param_1[1] == 0)) {
    return (byte *)0x0;
  }
  if ((bVar1 & 0x80) == 0) {
    *param_2 = (ushort)bVar1;
    param_1 = param_1 + 1;
  }
  else {
    *param_2 = (bVar1 & 0x7f) << 8 | (ushort)param_1[1];
    param_1 = param_1 + 2;
  }
  bVar1 = *param_1;
  if ((bVar1 & 0x80) != 0) {
    *param_3 = (short)((int)(short)((bVar1 & 0x7f) << 8 | (ushort)param_1[1]) << 1) >> 1;
    return param_1 + 2;
  }
  *param_3 = (short)((int)(short)(ushort)bVar1 << 9) >> 9;
  return param_1 + 1;
}

