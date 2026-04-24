// Function: FUN_80080610
// Entry: 80080610
// Size: 104 bytes

void FUN_80080610(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined8 uVar1;
  
  FUN_8000cfc0();
  uVar1 = FUN_8000cf74();
  if (DAT_803dc37c == 0xffffffff) {
    if (DAT_803dc378 != -1) {
      FUN_8001b7b4(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8001bc2c(DAT_803dc378);
      DAT_803dc378 = -1;
    }
  }
  else {
    FUN_8001bc8c(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dc37c);
    DAT_803dc37c = 0xffffffff;
    DAT_803dc374 = 0xffffffff;
  }
  return;
}

