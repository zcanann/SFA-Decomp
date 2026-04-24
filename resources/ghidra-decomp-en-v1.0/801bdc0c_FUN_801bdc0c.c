// Function: FUN_801bdc0c
// Entry: 801bdc0c
// Size: 120 bytes

void FUN_801bdc0c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar2 >> 0x20);
  if (param_6 != '\0') {
    FUN_8002fa48((double)FLOAT_803e4c80,(double)FLOAT_803db414,uVar1,0);
    FUN_8003b8f4((double)FLOAT_803e4c84,uVar1,(int)uVar2,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

