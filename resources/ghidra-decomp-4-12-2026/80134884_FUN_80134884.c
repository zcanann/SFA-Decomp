// Function: FUN_80134884
// Entry: 80134884
// Size: 676 bytes

void FUN_80134884(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  double dVar5;
  undefined8 local_28;
  
  FUN_80130124(0);
  if (DAT_803de608 == 4) {
    uVar4 = FUN_80019940(0xff,0xff,0xff,(byte)(int)FLOAT_803de5fc);
    FUN_80016848(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3dd,200,
                 DAT_803dc86c);
    if (DAT_803de5f8 == 0) {
      uVar1 = FUN_80134754(&DAT_8031d8a0,&DAT_803aaa30,(short *)&DAT_8031d888,6,(int *)&DAT_803aab98
                          );
      (**(code **)(*DAT_803dd720 + 4))(&DAT_803aaa30,uVar1,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
      DAT_803de5f8 = 1;
    }
    iVar2 = (**(code **)(*DAT_803dd720 + 0xc))();
    iVar3 = (**(code **)(*DAT_803dd720 + 0x14))();
    if (0 < iVar2) {
      (**(code **)(*DAT_803dd72c + 0x44))
                (0x42,(&DAT_8031d88a)[*(int *)(&DAT_803aab98 + iVar3 * 4) * 4]);
    }
    (**(code **)(*DAT_803dd720 + 0x10))(param_9);
    goto LAB_80134adc;
  }
  if (DAT_803de608 < 4) {
    if (DAT_803de608 == 1) {
      local_28 = (double)CONCAT44(0x43300000,DAT_803dc864 - 0x1dU ^ 0x80000000);
      dVar5 = (double)(float)((double)CONCAT44(0x43300000,DAT_803dc868 + 0xdU ^ 0x80000000) -
                             DOUBLE_803e2f60);
      FUN_80077318((double)(float)(local_28 - DOUBLE_803e2f60),dVar5,DAT_803de600,
                   (int)FLOAT_803de5fc,0xff);
      uVar4 = FUN_80019940(0xff,0xff,0xff,(byte)(int)FLOAT_803de5fc);
      uVar4 = FUN_800168a8(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,0x37c);
      uVar4 = FUN_800168a8(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,0x37d);
      FUN_800168a8(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,0x37e);
      goto LAB_80134adc;
    }
    if (DAT_803de608 == 0) goto LAB_80134adc;
  }
  else if (5 < DAT_803de608) goto LAB_80134adc;
  uVar4 = FUN_80019940(0xff,0xff,0xff,(byte)(int)FLOAT_803de5fc);
  FUN_80016848(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3dd,200,DAT_803dc860)
  ;
LAB_80134adc:
  if ((DAT_803de5f8 != 0) && (DAT_803de608 != 4)) {
    (**(code **)(*DAT_803dd720 + 8))();
    DAT_803de5f8 = 0;
  }
  return;
}

