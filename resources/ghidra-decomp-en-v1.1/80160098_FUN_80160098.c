// Function: FUN_80160098
// Entry: 80160098
// Size: 224 bytes

void FUN_80160098(uint param_1)

{
  short sVar1;
  int iVar2;
  
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cb) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x342,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x19);
  }
  else if ((sVar1 == 100) || (sVar1 == 0x30a)) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x344,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x19);
  }
  FUN_8000bb38(param_1,0x26a);
  FUN_8000faf8();
  FUN_8000e69c((double)FLOAT_803e3ae8);
  return;
}

