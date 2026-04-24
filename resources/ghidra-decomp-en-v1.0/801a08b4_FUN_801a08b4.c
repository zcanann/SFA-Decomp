// Function: FUN_801a08b4
// Entry: 801a08b4
// Size: 216 bytes

void FUN_801a08b4(short *param_1,int param_2)

{
  int iVar1;
  
  FUN_80037964(param_1,1);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(undefined4 *)(param_1 + 0x7a) = 1;
  *(code **)(param_1 + 0x5e) = FUN_801a0614;
  if (param_1[0x23] == 0x128) {
    iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
    if (iVar1 == 0) {
      FUN_80030334((double)FLOAT_803e42b4,param_1,0,0);
    }
    else {
      FUN_80030334((double)FLOAT_803e42b4,param_1,1,0);
    }
  }
  else {
    iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dca54 + 0x54))(param_1,0x3c);
    }
  }
  return;
}

