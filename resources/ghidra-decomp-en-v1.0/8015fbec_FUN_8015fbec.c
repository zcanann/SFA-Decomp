// Function: FUN_8015fbec
// Entry: 8015fbec
// Size: 224 bytes

void FUN_8015fbec(int param_1)

{
  short sVar1;
  int iVar2;
  
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cb) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x342,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x19);
  }
  else if ((sVar1 == 100) || (sVar1 == 0x30a)) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x344,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x19);
  }
  FUN_8000bb18(param_1,0x26a);
  FUN_8000fad8();
  FUN_8000e67c((double)FLOAT_803e2e50);
  return;
}

