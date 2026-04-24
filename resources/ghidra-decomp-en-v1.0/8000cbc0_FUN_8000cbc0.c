// Function: FUN_8000cbc0
// Entry: 8000cbc0
// Size: 300 bytes

double FUN_8000cbc0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined auStack40 [24];
  
  iVar1 = FUN_8002b9ec();
  iVar2 = FUN_8000faac();
  iVar3 = FUN_80080204();
  if ((iVar1 == 0) || (iVar3 != 0)) {
    if (iVar2 == 0) {
      return (double)FLOAT_803de570;
    }
    if (iVar1 == 0) {
      puVar4 = (undefined *)(iVar2 + 0x44);
    }
    else {
      FUN_80247754(iVar2 + 0x44,iVar1 + 0x18,auStack40);
      dVar7 = (double)FUN_802477f0(auStack40);
      dVar5 = (double)((float)(dVar7 - (double)FLOAT_803de5b4) / FLOAT_803de5b8);
      dVar7 = DOUBLE_803de5c8;
      if (DOUBLE_803de5c8 < dVar5) {
        dVar7 = dVar5;
      }
      dVar6 = DOUBLE_803de5c0;
      if ((dVar7 <= DOUBLE_803de5c0) && (dVar6 = DOUBLE_803de5c8, DOUBLE_803de5c8 < dVar5)) {
        dVar6 = dVar5;
      }
      FUN_80247778((double)(float)dVar6,auStack40,auStack40);
      FUN_80247730(iVar1 + 0x18,auStack40,auStack40);
      puVar4 = auStack40;
    }
  }
  else {
    puVar4 = (undefined *)(iVar1 + 0x18);
  }
  FUN_80247754(puVar4,param_1,param_2);
  dVar7 = (double)FUN_802477f0(param_2);
  return dVar7;
}

