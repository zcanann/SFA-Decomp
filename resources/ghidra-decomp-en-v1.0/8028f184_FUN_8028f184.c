// Function: FUN_8028f184
// Entry: 8028f184
// Size: 164 bytes

uint FUN_8028f184(int param_1,uint param_2)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  byte local_8 [8];
  
  if (param_1 == 0) {
    return 0;
  }
  if ((param_2 & 0xffff) < 0x80) {
    uVar2 = 1;
  }
  else if ((param_2 & 0xffff) < 0x800) {
    uVar2 = 2;
  }
  else {
    uVar2 = 3;
  }
  pbVar3 = (byte *)(param_1 + uVar2);
  if (uVar2 != 2) {
    if (uVar2 < 2) {
      if (uVar2 == 0) {
        return 0;
      }
      goto LAB_8028f20c;
    }
    if (3 < uVar2) {
      return uVar2;
    }
    bVar1 = (byte)param_2;
    param_2 = param_2 >> 6 & 0x3ff;
    pbVar3 = pbVar3 + -1;
    *pbVar3 = bVar1 & 0x3f | 0x80;
  }
  bVar1 = (byte)param_2;
  param_2 = param_2 >> 6 & 0x3ff;
  pbVar3 = pbVar3 + -1;
  *pbVar3 = bVar1 & 0x3f | 0x80;
LAB_8028f20c:
  pbVar3[-1] = (byte)param_2 | local_8[uVar2];
  return uVar2;
}

