// Function: FUN_80008cbc
// Entry: 80008cbc
// Size: 312 bytes

void FUN_80008cbc(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined auStack128 [92];
  byte bStack36;
  
  uVar3 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar3 >> 0x20);
  uVar2 = (undefined4)uVar3;
  FUN_8001f71c(auStack128,0x57,(param_3 & 0xffff) * 0x60,0x60);
  if (auStack128 != (undefined *)0x0) {
    if ((bStack36 < 3) || (bStack36 == 4)) {
      (**(code **)(*DAT_803dca60 + 4))(uVar1,uVar2,auStack128,param_4);
    }
    else if (bStack36 == 3) {
      (**(code **)(*DAT_803dca5c + 4))(uVar1,uVar2,auStack128,param_4,param_3);
    }
    else if (bStack36 == 5) {
      (**(code **)(*DAT_803dca58 + 4))(uVar1,uVar2,auStack128,param_4);
    }
    else if (bStack36 == 6) {
      (**(code **)(*DAT_803dca64 + 4))(uVar1,uVar2,auStack128,param_4,param_3);
    }
  }
  FUN_80286128(0);
  return;
}

