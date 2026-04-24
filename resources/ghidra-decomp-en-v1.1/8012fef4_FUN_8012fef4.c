// Function: FUN_8012fef4
// Entry: 8012fef4
// Size: 336 bytes

void FUN_8012fef4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int *piVar2;
  byte bVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286838();
  iVar1 = 0;
  piVar2 = &DAT_803a9610;
  do {
    if (*piVar2 != 0) {
      uVar4 = FUN_80054484();
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x66);
  FUN_8011f534(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  for (bVar3 = 0; bVar3 < 0x40; bVar3 = bVar3 + 1) {
    if ((&DAT_803a9e18)[bVar3] != 0) {
      FUN_80054484();
      (&DAT_803a9e18)[bVar3] = 0;
    }
    (&DAT_803a9d98)[bVar3] = 0xffff;
    (&DAT_803a9898)[bVar3] = 1;
  }
  if (DAT_803de448 != 0) {
    FUN_80054484();
    DAT_803de448 = 0;
  }
  if (DAT_803de4b4 != 0) {
    FUN_80054484();
  }
  DAT_803de4b0 = 0xffff;
  DAT_803de4b4 = 0;
  for (bVar3 = 0; bVar3 < 0x40; bVar3 = bVar3 + 1) {
    if ((&DAT_803a9e18)[bVar3] != 0) {
      FUN_80054484();
      (&DAT_803a9e18)[bVar3] = 0;
    }
    (&DAT_803a9d98)[bVar3] = 0xffff;
    (&DAT_803a9898)[bVar3] = 1;
  }
  FUN_80054484();
  FUN_80286884();
  return;
}

