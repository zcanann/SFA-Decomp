// Function: FUN_80038280
// Entry: 80038280
// Size: 112 bytes

void FUN_80038280(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_802860dc();
  for (iVar1 = 0; iVar1 < param_3; iVar1 = iVar1 + 1) {
    FUN_8003842c((int)((ulonglong)uVar2 >> 0x20),(int)uVar2 + iVar1,param_4,param_4 + 4,param_4 + 8,
                 0);
    param_4 = param_4 + 0xc;
  }
  FUN_80286128();
  return;
}

