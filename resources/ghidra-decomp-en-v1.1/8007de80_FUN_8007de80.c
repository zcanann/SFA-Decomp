// Function: FUN_8007de80
// Entry: 8007de80
// Size: 264 bytes

undefined4
FUN_8007de80(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,char param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,uint param_15,uint param_16)

{
  int iVar1;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 extraout_r4_01;
  undefined4 extraout_r4_02;
  undefined8 extraout_f1;
  undefined8 uVar2;
  
  if (param_9 != '\0') {
    DAT_803ddcd8 = '\0';
    param_1 = FUN_8007e7a0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    param_10 = extraout_r4;
  }
  do {
    iVar1 = FUN_8007fac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\0',
                         param_10,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar2 = CONCAT44(iVar1,param_10);
    if (iVar1 != 0) {
      if (DAT_803ddcda != '\0') {
        DAT_803ddcda = '\0';
        FUN_80263888((int *)&DAT_80397560);
      }
      FUN_80262bf4(0);
      param_1 = FUN_800238c4(DAT_803ddcc0);
      uVar2 = CONCAT44(iVar1,extraout_r4_00);
      DAT_803ddcc0 = 0;
      DAT_803dc360 = 0xd;
      if (iVar1 == 2) {
        param_11 = 0;
        param_12 = 0;
        param_13 = 0;
        param_14 = 0;
        uVar2 = FUN_8007ed98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0,0
                             ,0,(undefined *)0x0,param_15,param_16);
        param_1 = extraout_f1;
      }
    }
    param_10 = (undefined4)uVar2;
    if (param_9 != '\0') {
      param_1 = FUN_8007e328(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      param_10 = extraout_r4_01;
    }
    if (DAT_803ddcd8 != '\0') {
      param_1 = FUN_8007e7a0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      param_10 = extraout_r4_02;
    }
  } while ((DAT_803ddcd8 != '\0') && (param_9 != '\0'));
  return (int)((ulonglong)uVar2 >> 0x20);
}

