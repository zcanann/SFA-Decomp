// Function: FUN_80130044
// Entry: 80130044
// Size: 204 bytes

void FUN_80130044(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_80286838();
  FUN_8011f534(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  for (bVar1 = 0; bVar1 < 0x40; bVar1 = bVar1 + 1) {
    if ((&DAT_803a9e18)[bVar1] != 0) {
      FUN_80054484();
      (&DAT_803a9e18)[bVar1] = 0;
    }
    (&DAT_803a9d98)[bVar1] = 0xffff;
    (&DAT_803a9898)[bVar1] = 1;
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
  FUN_80286884();
  return;
}

