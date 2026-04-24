// Function: FUN_801d84c4
// Entry: 801d84c4
// Size: 396 bytes

void FUN_801d84c4(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 int *param_6)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286834();
  puVar3 = (uint *)((ulonglong)uVar7 >> 0x20);
  uVar5 = (uint)uVar7;
  uVar4 = (uint)param_3;
  uVar1 = -uVar4 - 1 | uVar4 + 1;
  uVar6 = (uint)param_4;
  uVar2 = -uVar6 - 1 | uVar6 + 1;
  if ((*puVar3 & uVar5) == 0) {
    if ((((int)uVar2 < 0) && (uVar4 = FUN_80020078(uVar6), uVar4 != 0)) ||
       (uVar4 = FUN_80020078((int)param_5), uVar4 != 0)) {
      if ((int)uVar1 < 0) {
        FUN_800201ac((int)param_3,0);
      }
      if ((int)uVar2 < 0) {
        FUN_800201ac((int)param_4,0);
      }
      FUN_800201ac((int)param_5,1);
      if (param_6 != (int *)0xffffffff) {
        FUN_8000a538(param_6,1);
      }
      *puVar3 = *puVar3 | uVar5;
    }
  }
  else if ((((int)uVar1 < 0) && (uVar4 = FUN_80020078(uVar4), uVar4 != 0)) ||
          (uVar4 = FUN_80020078((int)param_5), uVar4 == 0)) {
    if ((int)uVar1 < 0) {
      FUN_800201ac((int)param_3,0);
    }
    if ((int)uVar2 < 0) {
      FUN_800201ac((int)param_4,0);
    }
    FUN_800201ac((int)param_5,0);
    if (param_6 != (int *)0xffffffff) {
      FUN_8000a538(param_6,0);
    }
    *puVar3 = *puVar3 & ~uVar5;
  }
  FUN_80286880();
  return;
}

