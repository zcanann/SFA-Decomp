// Function: FUN_8028d5a8
// Entry: 8028d5a8
// Size: 68 bytes

void FUN_8028d5a8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined8 uVar1;
  
  DAT_803d94e0 = FUN_8028732c();
  if (DAT_803d94e0 == 0) {
    uVar1 = FUN_802872e0();
    FUN_80286fc0((int)((ulonglong)uVar1 >> 0x20),(int)uVar1,param_3,param_4,param_5,param_6,param_7,
                 param_8);
  }
  DAT_803d94e0 = FUN_80287308();
  return;
}

