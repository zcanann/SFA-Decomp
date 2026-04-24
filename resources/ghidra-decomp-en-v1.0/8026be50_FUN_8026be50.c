// Function: FUN_8026be50
// Entry: 8026be50
// Size: 144 bytes

int FUN_8026be50(byte **param_1)

{
  byte bVar1;
  uint uVar2;
  
  if (((uint)param_1[1] & 0xf) == 0) {
    *(byte *)(param_1 + 2) = **param_1 >> 4 & 7;
    *(byte *)((int)param_1 + 9) = **param_1 & 0xf;
    *param_1 = *param_1 + 1;
    param_1[1] = param_1[1] + 2;
  }
  if (((uint)param_1[1] & 1) == 0) {
    uVar2 = (uint)**param_1 << 0x18;
  }
  else {
    bVar1 = **param_1;
    *param_1 = *param_1 + 1;
    uVar2 = (uint)bVar1 << 0x1c | (uint)(bVar1 >> 4);
  }
  param_1[1] = param_1[1] + 1;
  return (int)uVar2 >> 0x1c;
}

