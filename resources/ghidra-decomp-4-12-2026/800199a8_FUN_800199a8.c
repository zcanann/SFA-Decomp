// Function: FUN_800199a8
// Entry: 800199a8
// Size: 420 bytes

void FUN_800199a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  int iVar2;
  undefined4 local_18 [5];
  
  iVar2 = DAT_803dd648;
  DAT_803dd627 = 0xff;
  DAT_803dd626 = 0xff;
  DAT_803dd625 = 0xff;
  DAT_803dd624 = 0xff;
  if (param_9 == 3) {
    DAT_803dd66c = &DAT_8033bbf0;
    DAT_803dd668 = 2;
    local_18[0] = DAT_803dc028;
    FUN_80075534(0,0,0xa00,0x780,local_18);
    iVar2 = DAT_803dd648;
    DAT_803dd61c = 0;
    if (DAT_803dd5ec == 0) {
      iVar1 = DAT_803dd648 * 5;
      DAT_803dd648 = DAT_803dd648 + 1;
      (&DAT_8033b1a0)[iVar1] = 0xf;
      (&DAT_8033b1a4)[iVar2 * 5] = 2;
    }
  }
  else {
    DAT_803dd65c = param_9;
    if (param_9 == 0x1c) {
      DAT_803dd66c = &DAT_8033bc18;
      DAT_803dd668 = 3;
      if (DAT_803dd5ec == 0) {
        iVar1 = DAT_803dd648 * 5;
        DAT_803dd648 = DAT_803dd648 + 1;
        (&DAT_8033b1a0)[iVar1] = 0xf;
        (&DAT_8033b1a4)[iVar2 * 5] = 3;
      }
      FUN_8001a6a4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    else {
      DAT_803dd66c = (undefined4 *)&DAT_8033bba0;
      DAT_803dd668 = 0;
      if (DAT_803dd5ec == 0) {
        iVar1 = DAT_803dd648 * 5;
        DAT_803dd648 = DAT_803dd648 + 1;
        (&DAT_8033b1a0)[iVar1] = 0xf;
        (&DAT_8033b1a4)[iVar2 * 5] = 0;
      }
      iVar2 = FUN_8001bd68();
      if (((iVar2 == 0) || (iVar2 = FUN_8001b500(param_9), iVar2 == 0)) &&
         (DAT_803dd65c != DAT_803dd658)) {
        FUN_8001a6a4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
  }
  return;
}

