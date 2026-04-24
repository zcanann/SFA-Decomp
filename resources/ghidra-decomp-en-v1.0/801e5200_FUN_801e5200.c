// Function: FUN_801e5200
// Entry: 801e5200
// Size: 120 bytes

void FUN_801e5200(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined8 uVar1;
  
  uVar1 = FUN_802860dc();
  if (param_6 != '\0') {
    FUN_80053ed0(8);
    FUN_8003b8f4((double)FLOAT_803e5928,(int)((ulonglong)uVar1 >> 0x20),(int)uVar1,param_3,param_4,
                 param_5);
    FUN_80053ebc(8);
  }
  FUN_80286128();
  return;
}

