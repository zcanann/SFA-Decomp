// Function: FUN_8007dca0
// Entry: 8007dca0
// Size: 156 bytes

void FUN_8007dca0(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)

{
  uint in_r9;
  uint in_r10;
  undefined8 extraout_f1;
  undefined8 uVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_80286840();
  DAT_803ddcd8 = '\0';
  uVar1 = FUN_8007e7a0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  do {
    uVar1 = FUN_8007ed98(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,
                         (int)((ulonglong)uVar2 >> 0x20),0,(int)uVar2,param_11,FUN_8007e928,in_r9,
                         in_r10);
    uVar1 = FUN_8007e328(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803ddcd8 != '\0') {
      uVar1 = FUN_8007e7a0(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  } while (DAT_803ddcd8 != '\0');
  FUN_8028688c();
  return;
}

