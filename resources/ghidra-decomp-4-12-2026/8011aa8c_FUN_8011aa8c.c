// Function: FUN_8011aa8c
// Entry: 8011aa8c
// Size: 304 bytes

void FUN_8011aa8c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  
  if (DAT_803dc65b != -1) {
    param_1 = (**(code **)(*DAT_803dd720 + 8))();
  }
  DAT_803dc65b = 0;
  DAT_803de324 = 0;
  FUN_8011a9b4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_8011a6b8((int *)&PTR_DAT_8031b40c);
  bVar1 = false;
  while (!bVar1) {
    if (DAT_803dc65c == 3) {
      PTR_DAT_8031b40c[0x1a] = 0xff;
    }
    else {
      PTR_DAT_8031b40c[0x1a] = 3;
    }
    bVar1 = true;
  }
  (**(code **)(*DAT_803dd720 + 4))
            (PTR_DAT_8031b40c,DAT_8031b410,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
  (**(code **)(*DAT_803dd720 + 0x18))(0);
  DAT_803de34e = 2;
  if (DAT_803dc084 == '\0') {
    FUN_8011a790();
  }
  return;
}

