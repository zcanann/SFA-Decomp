// Function: FUN_801b39c8
// Entry: 801b39c8
// Size: 152 bytes

void FUN_801b39c8(short *param_1,int param_2)

{
  char cVar1;
  
  **(undefined **)(param_1 + 0x5c) = 100;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  *(code **)(param_1 + 0x5e) = FUN_801b3768;
  FUN_80037200(param_1,0xf);
  cVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  if (cVar1 != '\0') {
    param_1[0x58] = param_1[0x58] | 0x8000;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

