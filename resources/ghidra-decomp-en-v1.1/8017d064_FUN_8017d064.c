// Function: FUN_8017d064
// Entry: 8017d064
// Size: 200 bytes

void FUN_8017d064(short *param_1,int param_2)

{
  uint uVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  FUN_8007d858();
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017ccfc;
  if (((-1 < *(short *)(param_2 + 0x20)) && ((int)*(short *)(param_2 + 0x18) != 0xffffffff)) &&
     (uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18)), uVar1 != 0)) {
    *pbVar2 = *pbVar2 | 1;
  }
  FUN_800372f8((int)param_1,0xf);
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

