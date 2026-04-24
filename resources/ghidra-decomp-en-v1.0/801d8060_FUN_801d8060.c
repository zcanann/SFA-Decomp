// Function: FUN_801d8060
// Entry: 801d8060
// Size: 148 bytes

void FUN_801d8060(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d4();
  iVar3 = (int)(short)param_5;
  uVar2 = FUN_8001ffb4(iVar3);
  uVar1 = countLeadingZeros(uVar2);
  FUN_800200e8(iVar3,uVar1 >> 5);
  FUN_801d7ed4((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,param_3,param_4,param_5,param_6);
  uVar2 = FUN_8001ffb4(iVar3);
  uVar1 = countLeadingZeros(uVar2);
  FUN_800200e8(iVar3,uVar1 >> 5);
  FUN_80286120();
  return;
}

