// Function: FUN_8020826c
// Entry: 8020826c
// Size: 168 bytes

void FUN_8020826c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  short sVar1;
  int *piVar2;
  
  if (param_10 == 0) {
    piVar2 = &DAT_803add98;
    for (sVar1 = 0; sVar1 < 4; sVar1 = sVar1 + 1) {
      if (*piVar2 != 0) {
        param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               *piVar2);
      }
      *piVar2 = 0;
      if (piVar2[1] != 0) {
        FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar2[1]);
      }
      piVar2[1] = 0;
      param_1 = FUN_8000bb38(param_9,0x1ce);
      piVar2 = piVar2 + 2;
    }
  }
  FUN_800146a8();
  return;
}

