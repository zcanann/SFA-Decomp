// Function: FUN_801ab800
// Entry: 801ab800
// Size: 256 bytes

void FUN_801ab800(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(0xdc5);
  if (iVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 4));
  if (iVar1 == 0) {
    FUN_8002b884(param_1,1);
    iVar1 = FUN_80038024(param_1);
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      FUN_8001ff3c(0xa9);
      *(byte *)(param_2 + 6) = *(byte *)(param_2 + 6) | 1;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8002b884(param_1,0);
  }
  return;
}

