// Function: FUN_8005c968
// Entry: 8005c968
// Size: 608 bytes

void FUN_8005c968(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)

{
  double dVar1;
  int iVar2;
  int *piVar3;
  float *pfVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  if (param_9 == 0) {
    FUN_80088b10(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    (**(code **)(*DAT_803dd6e4 + 0xc))();
    (**(code **)(*DAT_803dd6dc + 0xc))();
    (**(code **)(*DAT_803dd6d8 + 0xc))();
    dVar7 = (double)(**(code **)(*DAT_803dd6e0 + 0x10))();
    iVar6 = 0;
    iVar5 = 0;
    do {
      piVar3 = (int *)(DAT_803ddaec + iVar5);
      if ((((*(short *)(piVar3 + 3) != 0) && (iVar2 = *piVar3, iVar2 != 0)) &&
          (*(short *)(iVar2 + 0x10) != 0x100)) && (*(short *)(iVar2 + 0x14) != 0)) {
        dVar7 = (double)FUN_800540a8(iVar2,(uint *)(piVar3 + 2),piVar3 + 1);
      }
      iVar5 = iVar5 + 0x10;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x50);
    iVar5 = 0;
    iVar6 = 0x1d;
    do {
      dVar1 = DOUBLE_803df840;
      pfVar4 = (float *)(DAT_803ddae8 + iVar5);
      if (*(char *)(pfVar4 + 3) != '\0') {
        param_4 = (double)FLOAT_803dc074;
        param_3 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)((int)pfVar4 + 10)
                                                                   ^ 0x80000000) - DOUBLE_803df840)
                                 * param_4);
        dVar7 = (double)*pfVar4;
        *pfVar4 = (float)(dVar7 + (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                   (int)*(short *)(
                                                  pfVar4 + 2) ^ 0x80000000) - DOUBLE_803df840) *
                                                 param_4));
        pfVar4[1] = (float)((double)pfVar4[1] + param_3);
        param_2 = dVar1;
      }
      dVar1 = DOUBLE_803df840;
      pfVar4 = (float *)(DAT_803ddae8 + iVar5 + 0x10);
      if (*(char *)(pfVar4 + 3) != '\0') {
        param_4 = (double)FLOAT_803dc074;
        param_3 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)((int)pfVar4 + 10)
                                                                   ^ 0x80000000) - DOUBLE_803df840)
                                 * param_4);
        dVar7 = (double)*pfVar4;
        *pfVar4 = (float)(dVar7 + (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                   (int)*(short *)(
                                                  pfVar4 + 2) ^ 0x80000000) - DOUBLE_803df840) *
                                                 param_4));
        pfVar4[1] = (float)((double)pfVar4[1] + param_3);
        param_2 = dVar1;
      }
      iVar5 = iVar5 + 0x20;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    FUN_800552ac(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803dd730 != (int *)0x0) {
      (**(code **)(*DAT_803dd730 + 8))();
    }
    (**(code **)(*DAT_803dd73c + 4))();
    if (DAT_803dda80 != 0) {
      DAT_803dda7c = DAT_803dda7c + DAT_803dda80;
      if (DAT_803dda7c < 0) {
        DAT_803dda7c = 0;
        DAT_803dda80 = 0;
      }
      else if (0xff < DAT_803dda7c) {
        DAT_803dda7c = 0xff;
        DAT_803dda80 = 0;
      }
    }
  }
  return;
}

