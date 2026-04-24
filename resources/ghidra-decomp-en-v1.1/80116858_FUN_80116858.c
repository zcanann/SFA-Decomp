// Function: FUN_80116858
// Entry: 80116858
// Size: 264 bytes

void FUN_80116858(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)

{
  char cVar2;
  int iVar1;
  undefined8 extraout_f1;
  double dVar3;
  double dVar4;
  
  cVar2 = FUN_80134f44();
  if (cVar2 == '\0') {
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar1 == 0x57) {
      FUN_8001b4f8(FUN_80135e18);
      dVar4 = (double)FLOAT_803e2998;
      FUN_80135ba8((double)(FLOAT_803e2990 +
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803de28e * 0x1a4 ^ 0x80000000) -
                                  DOUBLE_803e29a0) / FLOAT_803e2994),dVar4);
      FUN_801350c8(0,0,0);
      (**(code **)(*DAT_803dd6cc + 0x18))();
      (**(code **)(*DAT_803dd720 + 0x30))(0xff);
      (**(code **)(*DAT_803dd720 + 0x10))(param_9);
      dVar3 = (double)FUN_8001b4f8(0);
      FUN_80134fb0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de2cf);
    }
  }
  else {
    FUN_80134d50(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

