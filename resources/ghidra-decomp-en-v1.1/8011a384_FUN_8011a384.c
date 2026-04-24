// Function: FUN_8011a384
// Entry: 8011a384
// Size: 420 bytes

void FUN_8011a384(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  char cVar2;
  undefined8 uVar3;
  undefined8 extraout_f1;
  
  iVar1 = (int)DAT_803dc65b;
  if (param_9 == 0) {
    if (DAT_803de338 != 0) {
      (**(code **)(*DAT_803dd724 + 0x10))();
      DAT_803de338 = 0;
    }
    uVar3 = FUN_8000bb38(0,0x419);
    FUN_8011aa8c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else {
    FUN_8000bb38(0,0x418);
    if (DAT_803de345 == '\0') {
      if (param_10 == 0) {
        FUN_8011a790();
      }
      else {
        *(ushort *)((&PTR_DAT_8031b40c)[iVar1 * 3] + 0x16) =
             *(ushort *)((&PTR_DAT_8031b40c)[iVar1 * 3] + 0x16) | 0x4000;
        (&PTR_DAT_8031b40c)[iVar1 * 3][0x56] = 0xff;
        *(undefined2 *)((&PTR_DAT_8031b40c)[iVar1 * 3] + 0x3c) = 0x3d8;
        DAT_803de345 = '\x01';
        DAT_803de338 = (**(code **)(*DAT_803dd724 + 0xc))(0x3d7,0x29,0,1,0);
        (**(code **)(*DAT_803dd724 + 0x20))(DAT_803de338,1);
        (**(code **)(*DAT_803dd720 + 0x2c))((&PTR_DAT_8031b40c)[iVar1 * 3]);
      }
    }
    else {
      cVar2 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803de338);
      if (cVar2 == '\x01') {
        FUN_800e8824(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     DAT_803de324);
      }
      uVar3 = (**(code **)(*DAT_803dd724 + 0x10))(DAT_803de338);
      DAT_803de338 = 0;
      FUN_8011aa8c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  return;
}

