// Function: FUN_801d7ed4
// Entry: 801d7ed4
// Size: 396 bytes

void FUN_801d7ed4(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 int param_6)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860d0();
  puVar3 = (uint *)((ulonglong)uVar6 >> 0x20);
  uVar4 = (uint)uVar6;
  uVar1 = -(int)param_3 - 1U | (int)param_3 + 1U;
  iVar5 = (int)param_4;
  uVar2 = -iVar5 - 1U | iVar5 + 1U;
  if ((*puVar3 & uVar4) == 0) {
    if ((((int)uVar2 < 0) && (iVar5 = FUN_8001ffb4(iVar5), iVar5 != 0)) ||
       (iVar5 = FUN_8001ffb4((int)param_5), iVar5 != 0)) {
      if ((int)uVar1 < 0) {
        FUN_800200e8((int)param_3,0);
      }
      if ((int)uVar2 < 0) {
        FUN_800200e8((int)param_4,0);
      }
      FUN_800200e8((int)param_5,1);
      if (param_6 != -1) {
        FUN_8000a518(param_6,1);
      }
      *puVar3 = *puVar3 | uVar4;
    }
  }
  else if ((((int)uVar1 < 0) && (iVar5 = FUN_8001ffb4(), iVar5 != 0)) ||
          (iVar5 = FUN_8001ffb4((int)param_5), iVar5 == 0)) {
    if ((int)uVar1 < 0) {
      FUN_800200e8((int)param_3,0);
    }
    if ((int)uVar2 < 0) {
      FUN_800200e8((int)param_4,0);
    }
    FUN_800200e8((int)param_5,0);
    if (param_6 != -1) {
      FUN_8000a518(param_6,0);
    }
    *puVar3 = *puVar3 & ~uVar4;
  }
  FUN_8028611c();
  return;
}

