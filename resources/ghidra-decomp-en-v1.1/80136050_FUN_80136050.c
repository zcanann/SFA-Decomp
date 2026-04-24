// Function: FUN_80136050
// Entry: 80136050
// Size: 2784 bytes

void FUN_80136050(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  char *pcVar9;
  int iVar10;
  double dVar11;
  undefined8 extraout_f1;
  double dVar12;
  undefined8 uVar13;
  undefined auStack_48 [27];
  undefined local_2d;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  
  iVar10 = *(int *)(param_9 + 0x5c);
  if (DAT_803de62b != '\0') {
    if ((((*(char *)(iVar10 + 0x31) != DAT_803de610) && (DAT_803de611 == '\0')) &&
        (cVar1 = *(char *)(iVar10 + 0x30), cVar1 != '\0')) &&
       ((cVar1 != '\x04' && (cVar1 != '\x03')))) {
      if ((param_9[0x23] == 0x77d) || (param_9[0x23] == 0x780)) {
        *(undefined *)(iVar10 + 0x30) = 3;
        param_1 = (double)FUN_8003042c((double)FLOAT_803e2fa8,param_2,param_3,param_4,param_5,
                                       param_6,param_7,param_8,param_9,1,0,param_12,param_13,
                                       param_14,param_15,param_16);
        *(undefined **)(iVar10 + 0x34) = (&PTR_DAT_8030eacc)[param_9[0x23] * 8];
      }
      else {
        *(undefined *)(iVar10 + 0x30) = 0;
        param_1 = (double)FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,
                                       param_6,param_7,param_8,param_9,0,0,param_12,param_13,
                                       param_14,param_15,param_16);
        *(undefined4 *)(iVar10 + 0x34) = *(undefined4 *)(&DAT_8030eac0 + param_9[0x23] * 0x20);
      }
    }
    if (((*(char *)(iVar10 + 0x31) == DAT_803de610) && (DAT_803de611 != '\0')) &&
       ((cVar1 = *(char *)(iVar10 + 0x30), cVar1 != '\x01' &&
        ((cVar1 != '\x02' && (cVar1 != '\x05')))))) {
      *(undefined *)(iVar10 + 0x30) = 1;
      param_1 = (double)FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,
                                     param_7,param_8,param_9,1,0,param_12,param_13,param_14,param_15
                                     ,param_16);
      *(undefined4 *)(iVar10 + 0x34) = *(undefined4 *)(&DAT_8030eac4 + param_9[0x23] * 0x20);
      if (param_9[0x23] == 0x77e) {
        FUN_8000b844((int)param_9,0x370);
        FUN_8000b844((int)param_9,0x36c);
        param_1 = (double)FUN_8000bb38((uint)param_9,0x36d);
      }
    }
    dVar11 = DOUBLE_803e2f78;
    sVar2 = param_9[0x23];
    if (sVar2 == 0x7a7) {
      param_3 = (double)FLOAT_803e2fe4;
      param_2 = (double)FLOAT_803dc074;
      uStack_24 = (int)*param_9 ^ 0x80000000;
      local_28 = 0x43300000;
      iVar4 = (int)(param_3 * param_2 +
                   (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2f78));
      local_20 = (double)(longlong)iVar4;
      *param_9 = (short)iVar4;
      param_1 = dVar11;
    }
    else if (sVar2 != 0x78a) {
      local_2d = 0;
      if ((sVar2 == 0x77d) && (*(char *)(iVar10 + 0x30) == '\x02')) {
        if (FLOAT_803e2fe8 <= *(float *)(param_9 + 0x4c)) {
          dVar11 = (double)FLOAT_803dc874;
        }
        else {
          uVar5 = FUN_80022264(0x32,0x96);
          local_20 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          FLOAT_803dc874 = FLOAT_803e2fec * (float)(local_20 - DOUBLE_803e2f78);
          dVar11 = (double)FLOAT_803dc874;
        }
      }
      else {
        dVar11 = (double)*(float *)(iVar10 + 0x34);
      }
      param_2 = (double)FLOAT_803dc074;
      iVar4 = FUN_8002fb40(dVar11,param_2);
      if (iVar4 != 0) {
        if ((*(char *)(iVar10 + 0x31) == DAT_803de610) && (*(char *)(iVar10 + 0x30) == '\x01')) {
          *(undefined *)(iVar10 + 0x30) = 2;
          FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,2,0,param_12,param_13,param_14,param_15,param_16);
          *(undefined **)(iVar10 + 0x34) = (&PTR_DAT_8030eac8)[param_9[0x23] * 8];
        }
        else if (*(char *)(iVar10 + 0x30) == '\x03') {
          *(undefined *)(iVar10 + 0x30) = 0;
          FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
          *(undefined4 *)(iVar10 + 0x34) = *(undefined4 *)(&DAT_8030eac0 + param_9[0x23] * 0x20);
        }
        else if ((0x77c < param_9[0x23]) && (param_9[0x23] < 0x781)) {
          uVar5 = FUN_80022264(0,4);
          if (uVar5 == 0) {
            if ((*(char *)(iVar10 + 0x30) == '\0') || (*(char *)(iVar10 + 0x30) == '\x04')) {
              *(undefined *)(iVar10 + 0x30) = 4;
              uVar5 = FUN_80022264(3,4);
              FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,uVar5,0,param_12,param_13,param_14,param_15,param_16);
              *(undefined4 *)(iVar10 + 0x34) =
                   *(undefined4 *)(&DAT_8030eac4 + param_9[0x23] * 0x20 + param_9[0x50] * 4);
            }
            else {
              *(undefined *)(iVar10 + 0x30) = 5;
              uVar5 = FUN_80022264(5,6);
              FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,uVar5,0,param_12,param_13,param_14,param_15,param_16);
              *(undefined4 *)(iVar10 + 0x34) =
                   *(undefined4 *)(&DAT_8030eac4 + param_9[0x23] * 0x20 + param_9[0x50] * 4);
            }
          }
          else if (*(char *)(iVar10 + 0x30) == '\x04') {
            *(undefined *)(iVar10 + 0x30) = 0;
            FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
            *(undefined4 *)(iVar10 + 0x34) = *(undefined4 *)(&DAT_8030eac0 + param_9[0x23] * 0x20);
          }
          else if (*(char *)(iVar10 + 0x30) == '\x05') {
            *(undefined *)(iVar10 + 0x30) = 2;
            FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,2,0,param_12,param_13,param_14,param_15,param_16);
            *(undefined **)(iVar10 + 0x34) = (&PTR_DAT_8030eac8)[param_9[0x23] * 8];
          }
        }
      }
      param_1 = (double)FUN_80134bf8((uint)param_9,(int)auStack_48);
    }
    sVar2 = param_9[0x23];
    if ((sVar2 == 0x77e) &&
       ((*(char *)(iVar10 + 0x30) == '\0' || (*(char *)(iVar10 + 0x30) == '\x04')))) {
      param_1 = (double)FUN_8003b320((int)param_9,iVar10);
    }
    else if ((0x77c < sVar2) && (sVar2 < 0x781)) {
      param_1 = (double)FUN_8003b408((int)param_9,iVar10);
    }
    piVar3 = (int *)FUN_8002b660((int)param_9);
    if (((*(char *)(*piVar3 + 0xf9) != '\0') && (iVar4 = FUN_800279a8(piVar3), iVar4 == 0)) &&
       (uVar5 = FUN_80022264(0xf0,0x168), uVar5 == 0xf0)) {
      iVar4 = piVar3[10];
      uVar5 = FUN_80022264(0,(uint)*(byte *)(*piVar3 + 0xf9));
      param_13 = 0;
      param_1 = (double)FUN_80027a90((double)FLOAT_803e2ff0,piVar3,0,(int)*(char *)(iVar4 + 0xd),
                                     uVar5 - 1,0);
    }
    DAT_803dc870 = 0xff;
    DAT_803dc871 = 0xff;
    uVar5 = (uint)*(byte *)(iVar10 + 0x30);
    iVar10 = (int)param_9[0x23];
    if (iVar10 == 0x77f) {
      if (((uVar5 < 6) && (3 < uVar5)) && ((param_9[0x50] == 3 || (param_9[0x50] == 5)))) {
        iVar10 = uVar5 * 3;
        if (*(char *)(iVar10 + -0x7fc5542c) == '\0') {
          if (FLOAT_803e2ff8 < *(float *)(param_9 + 0x4c)) {
            FUN_8000bb38((uint)param_9,0x421);
            *(undefined *)(iVar10 + -0x7fc5542c) = 1;
          }
        }
        else if (*(float *)(param_9 + 0x4c) < FLOAT_803e2ff8) {
          *(undefined *)(iVar10 + -0x7fc5542c) = 0;
        }
        pcVar9 = (char *)((param_9[0x23] + -0x77d) * 0x12 + iVar10 + -0x7fc5544f);
        if (*pcVar9 == '\0') {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if ((double)FLOAT_803e2ffc < param_1) {
            param_1 = (double)FUN_8000bb38((uint)param_9,0x421);
            *pcVar9 = '\x01';
          }
        }
        else {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if (param_1 < (double)FLOAT_803e2ffc) {
            *pcVar9 = '\0';
          }
        }
      }
    }
    else if (iVar10 < 0x77f) {
      if (((iVar10 != 0x77d) && (0x77c < iVar10)) && (uVar5 == 5)) {
        iVar10 = (iVar10 + -0x77d) * 0x12;
        if (*(char *)(iVar10 + -0x7fc55441) == '\0') {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if ((double)FLOAT_803e2ff4 < param_1) {
            param_1 = (double)FUN_8000bb38((uint)param_9,0x41d);
            *(undefined *)(iVar10 + -0x7fc55441) = 1;
          }
        }
        else {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if (param_1 < (double)FLOAT_803e2ff4) {
            *(undefined *)(iVar10 + -0x7fc55441) = 0;
          }
        }
      }
    }
    else if (iVar10 < 0x781) {
      if (uVar5 == 4) {
        iVar10 = (iVar10 + -0x77d) * 0x12;
        if (*(char *)(iVar10 + -0x7fc55444) == '\0') {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if ((double)FLOAT_803e3000 < param_1) {
            param_1 = (double)FUN_8000bb38((uint)param_9,0x414);
            *(undefined *)(iVar10 + -0x7fc55444) = 1;
          }
        }
        else {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if (param_1 < (double)FLOAT_803e3000) {
            *(undefined *)(iVar10 + -0x7fc55444) = 0;
          }
        }
      }
      else if (uVar5 < 4) {
        if (uVar5 == 2) {
          iVar10 = (iVar10 + -0x77d) * 0x12;
          if (*(char *)(iVar10 + -0x7fc5544a) == '\0') {
            if (FLOAT_803e2ff8 < *(float *)(param_9 + 0x4c)) {
              FUN_8000bb38((uint)param_9,0x426);
              *(undefined *)(iVar10 + -0x7fc5544a) = 1;
            }
          }
          else if (*(float *)(param_9 + 0x4c) < FLOAT_803e2ff8) {
            *(undefined *)(iVar10 + -0x7fc5544a) = 0;
          }
          pcVar9 = (char *)((param_9[0x23] + -0x77d) * 0x12 + -0x7fc55449);
          if (*pcVar9 == '\0') {
            if (FLOAT_803e3010 < *(float *)(param_9 + 0x4c)) {
              FUN_8000bb38((uint)param_9,0x426);
              *pcVar9 = '\x01';
            }
          }
          else if (*(float *)(param_9 + 0x4c) < FLOAT_803e3010) {
            *pcVar9 = '\0';
          }
          pcVar9 = (char *)((param_9[0x23] + -0x77d) * 0x12 + -0x7fc55448);
          if (*pcVar9 == '\0') {
            param_1 = (double)*(float *)(param_9 + 0x4c);
            if ((double)FLOAT_803e3014 < param_1) {
              param_1 = (double)FUN_8000bb38((uint)param_9,0x426);
              *pcVar9 = '\x01';
            }
          }
          else {
            param_1 = (double)*(float *)(param_9 + 0x4c);
            if (param_1 < (double)FLOAT_803e3014) {
              *pcVar9 = '\0';
            }
          }
        }
      }
      else if (uVar5 < 6) {
        iVar10 = (iVar10 + -0x77d) * 0x12 + -0x7fc55450;
        iVar4 = uVar5 * 3;
        if (*(char *)(iVar10 + iVar4) == '\0') {
          if (FLOAT_803e3004 < *(float *)(param_9 + 0x4c)) {
            FUN_8000bb38((uint)param_9,0x412);
            *(undefined *)(iVar10 + iVar4) = 1;
          }
        }
        else if (*(float *)(param_9 + 0x4c) < FLOAT_803e3004) {
          *(undefined *)(iVar10 + iVar4) = 0;
        }
        pcVar9 = (char *)((param_9[0x23] + -0x77d) * 0x12 + iVar4 + -0x7fc5544f);
        if (*pcVar9 == '\0') {
          if (FLOAT_803e3008 < *(float *)(param_9 + 0x4c)) {
            FUN_8000bb38((uint)param_9,0x426);
            *pcVar9 = '\x01';
          }
        }
        else if (*(float *)(param_9 + 0x4c) < FLOAT_803e3008) {
          *pcVar9 = '\0';
        }
        pcVar9 = (char *)((param_9[0x23] + -0x77d) * 0x12 + iVar4 + -0x7fc5544e);
        if (*pcVar9 == '\0') {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if ((double)FLOAT_803e300c < param_1) {
            param_1 = (double)FUN_8000bb38((uint)param_9,0x413);
            *pcVar9 = '\x01';
          }
        }
        else {
          param_1 = (double)*(float *)(param_9 + 0x4c);
          if (param_1 < (double)FLOAT_803e300c) {
            *pcVar9 = '\0';
          }
        }
      }
    }
    if (DAT_803de612 == '\0') {
      FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x21f,0,
                   param_13,param_14,param_15,param_16);
      FUN_8008999c(7,1,0);
      uVar6 = 0x78;
      uVar7 = 0;
      uVar8 = 0;
      FUN_8008986c(7,0x4b,100,0x78,0,0);
      dVar12 = (double)FLOAT_803e3018;
      dVar11 = dVar12;
      FUN_80089734((double)FLOAT_803e2fa8,dVar12,dVar12,7);
      iVar10 = *DAT_803dd6d0;
      uVar13 = (**(code **)(iVar10 + 0x28))(param_9,0);
      DAT_803de612 = '\x01';
      FUN_80132294(extraout_f1,dVar12,dVar11,param_4,param_5,param_6,param_7,param_8,
                   (int)((ulonglong)uVar13 >> 0x20),(int)uVar13,iVar10,uVar6,uVar7,uVar8,param_15,
                   param_16);
    }
  }
  return;
}

