// Function: FUN_801f7c64
// Entry: 801f7c64
// Size: 136 bytes

void FUN_801f7c64(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  if (((**(short **)(iVar1 + 0xb8) == -1) || (iVar2 = FUN_8001ffb4(), iVar2 != 0)) &&
     (param_6 != '\0')) {
    FUN_8003b8f4((double)FLOAT_803e5f90,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286124();
  return;
}

