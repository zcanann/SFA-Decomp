// Function: FUN_80008b74
// Entry: 80008b74
// Size: 328 bytes

void FUN_80008b74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 extraout_f1;
  undefined8 uVar3;
  undefined auStack_80 [42];
  undefined2 uStack_56;
  byte bStack_24;
  
  uVar3 = FUN_80286840();
  uVar1 = (undefined4)((ulonglong)uVar3 >> 0x20);
  uVar2 = (undefined4)uVar3;
  FUN_8001f7e0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,auStack_80,0x57,
               (param_11 & 0xffff) * 0x60,0x60,param_13,param_14,param_15,param_16);
  if (auStack_80 != (undefined *)0x0) {
    if ((bStack_24 < 3) || (bStack_24 == 4)) {
      (**(code **)(*DAT_803dd6e0 + 4))(uVar1,uVar2,auStack_80,param_12);
    }
    else if (bStack_24 == 3) {
      uStack_56 = 0;
      (**(code **)(*DAT_803dd6dc + 4))(uVar1,uVar2,auStack_80,param_12,param_11);
    }
    else if (bStack_24 == 5) {
      uStack_56 = 0;
      (**(code **)(*DAT_803dd6d8 + 4))(uVar1,uVar2,auStack_80,param_12);
    }
    else if (bStack_24 == 6) {
      (**(code **)(*DAT_803dd6e4 + 4))(uVar1,uVar2,auStack_80,param_12,param_11);
    }
  }
  FUN_8028688c();
  return;
}

