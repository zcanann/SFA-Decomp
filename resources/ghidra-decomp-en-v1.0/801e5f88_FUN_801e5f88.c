// Function: FUN_801e5f88
// Entry: 801e5f88
// Size: 112 bytes

void FUN_801e5f88(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1e));
  if (iVar2 != 0) {
    FUN_8003b8f4((double)FLOAT_803e59c0,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

