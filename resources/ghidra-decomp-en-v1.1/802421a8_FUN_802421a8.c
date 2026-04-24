// Function: FUN_802421a8
// Entry: 802421a8
// Size: 48 bytes

uint FUN_802421a8(uint param_1,int param_2)

{
  uint uVar1;
  
  if (param_2 == 0) {
    return param_1;
  }
  if ((param_1 & 0x1f) != 0) {
    param_2 = param_2 + 0x20;
  }
  uVar1 = param_2 + 0x1fU >> 5;
  do {
    dataCacheBlockClearToZero(param_1);
    param_1 = param_1 + 0x20;
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  return param_1;
}

