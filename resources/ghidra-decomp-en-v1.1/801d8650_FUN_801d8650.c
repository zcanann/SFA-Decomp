// Function: FUN_801d8650
// Entry: 801d8650
// Size: 148 bytes

void FUN_801d8650(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 int *param_6)

{
  uint uVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_80286838();
  uVar2 = (uint)param_5;
  uVar1 = FUN_80020078(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  FUN_800201ac(uVar2,uVar1 >> 5);
  FUN_801d84c4((int)((ulonglong)uVar3 >> 0x20),(int)uVar3,param_3,param_4,param_5,param_6);
  uVar1 = FUN_80020078(uVar2);
  uVar1 = countLeadingZeros(uVar1);
  FUN_800201ac(uVar2,uVar1 >> 5);
  FUN_80286884();
  return;
}

