// Function: FUN_801fda24
// Entry: 801fda24
// Size: 120 bytes

void FUN_801fda24(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined8 uVar1;
  
  uVar1 = FUN_802860dc();
  if (param_6 != '\0') {
    FUN_8003b608(0xff,0xe6,0xd7);
    FUN_8003b8f4((double)FLOAT_803e6168,(int)((ulonglong)uVar1 >> 0x20),(int)uVar1,param_3,param_4,
                 param_5);
  }
  FUN_80286128();
  return;
}

