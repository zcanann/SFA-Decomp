// Function: FUN_801ecec4
// Entry: 801ecec4
// Size: 208 bytes

void FUN_801ecec4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  FUN_801e991c(iVar1,iVar2);
  if (param_6 == -1) {
    FUN_8003b8f4((double)FLOAT_803e5aec,iVar1,(int)uVar3,param_3,param_4,param_5);
    FUN_8003842c(iVar1,0,iVar2 + 1000,iVar2 + 0x3ec,iVar2 + 0x3f0,0);
  }
  else {
    FUN_8003b8f4((double)FLOAT_803e5aec,iVar1,(int)uVar3,param_3,param_4,param_5);
    FUN_8003842c(iVar1,0,iVar2 + 1000,iVar2 + 0x3ec,iVar2 + 0x3f0,0);
  }
  FUN_80286120();
  return;
}

