// Function: FUN_8012fe84
// Entry: 8012fe84
// Size: 92 bytes

undefined4
FUN_8012fe84(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined8 uVar1;
  
  if (DAT_803de445 != '\0') {
    if (DAT_803de3fe != '\0') {
      FUN_8012dca8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    uVar1 = FUN_8012e050();
    if (DAT_803de413 != '\0') {
      uVar1 = FUN_8012e2a4(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    FUN_8012ecb8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return 0;
}

