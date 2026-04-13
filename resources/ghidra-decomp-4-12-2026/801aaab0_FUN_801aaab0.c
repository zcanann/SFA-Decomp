// Function: FUN_801aaab0
// Entry: 801aaab0
// Size: 92 bytes

void FUN_801aaab0(short *param_1,int param_2)

{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801aa55c;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  uVar1 = FUN_80020078(0xa3);
  if (uVar1 != 0) {
    *puVar2 = 7;
  }
  return;
}

