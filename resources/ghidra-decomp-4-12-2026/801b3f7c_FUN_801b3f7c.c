// Function: FUN_801b3f7c
// Entry: 801b3f7c
// Size: 152 bytes

void FUN_801b3f7c(short *param_1,int param_2)

{
  uint uVar1;
  
  **(undefined **)(param_1 + 0x5c) = 100;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  *(code **)(param_1 + 0x5e) = FUN_801b3d1c;
  FUN_800372f8((int)param_1,0xf);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  if ((uVar1 & 0xff) != 0) {
    param_1[0x58] = param_1[0x58] | 0x8000;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

