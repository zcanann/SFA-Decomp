// Function: FUN_8013422c
// Entry: 8013422c
// Size: 156 bytes

void FUN_8013422c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  undefined8 uVar2;
  
  if (DAT_803de5bc != 0) {
    FUN_80054484();
  }
  uVar2 = FUN_80054484();
  for (bVar1 = 0; bVar1 < 2; bVar1 = bVar1 + 1) {
    if (*(int *)(&DAT_803dc830 + (uint)bVar1 * 4) != 0) {
      uVar2 = FUN_8002cc9c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(&DAT_803dc830 + (uint)bVar1 * 4));
      *(undefined4 *)(&DAT_803dc830 + (uint)bVar1 * 4) = 0;
    }
  }
  DAT_803de5bc = 0;
  DAT_803de5c0 = 0;
  return;
}

