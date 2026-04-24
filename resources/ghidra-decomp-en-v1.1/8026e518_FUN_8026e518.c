// Function: FUN_8026e518
// Entry: 8026e518
// Size: 164 bytes

byte * FUN_8026e518(byte *param_1,ushort *param_2,short *param_3)

{
  byte bVar1;
  byte *pbVar2;
  
  bVar1 = *param_1;
  if ((bVar1 == 0x80) && (param_1[1] == 0)) {
    return (byte *)0x0;
  }
  if ((bVar1 & 0x80) == 0) {
    *param_2 = (ushort)bVar1;
    pbVar2 = param_1 + 1;
  }
  else {
    *param_2 = (bVar1 & 0x7f) << 8 | (ushort)param_1[1];
    pbVar2 = param_1 + 2;
  }
  bVar1 = *pbVar2;
  if ((bVar1 & 0x80) != 0) {
    *param_3 = (short)((int)(short)((bVar1 & 0x7f) << 8 | (ushort)pbVar2[1]) << 1) >> 1;
    return pbVar2 + 2;
  }
  *param_3 = (short)((int)(short)(ushort)bVar1 << 9) >> 9;
  return pbVar2 + 1;
}

