// Function: FUN_8002e088
// Entry: 8002e088
// Size: 188 bytes

void FUN_8002e088(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,undefined4 param_12,
                 uint *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  undefined8 extraout_f1;
  undefined8 uVar3;
  undefined8 extraout_f1_00;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  uVar3 = extraout_f1;
  uVar1 = FUN_800431a4();
  if ((uVar1 & 0x100000) == 0) {
    iVar2 = FUN_8002d654(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)((ulonglong)uVar4 >> 0x20),(uint)uVar4,param_11,param_12,param_13,0,
                         param_15,param_16);
    if (iVar2 != 0) {
      FUN_8002d404(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
                   (uint)uVar4);
      FUN_8007d858();
    }
  }
  else {
    FUN_8007d858();
  }
  FUN_8028688c();
  return;
}

