// Function: FUN_80135cc8
// Entry: 80135cc8
// Size: 2784 bytes

void FUN_80135cc8(short *param_1)

{
  char cVar1;
  short sVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  char *pcVar8;
  int iVar9;
  double dVar10;
  undefined auStack72 [27];
  undefined local_2d;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  
  iVar9 = *(int *)(param_1 + 0x5c);
  if (DAT_803dd9ab != '\0') {
    if ((((*(char *)(iVar9 + 0x31) != DAT_803dd990) && (DAT_803dd991 == '\0')) &&
        (cVar1 = *(char *)(iVar9 + 0x30), cVar1 != '\0')) &&
       ((cVar1 != '\x04' && (cVar1 != '\x03')))) {
      if ((param_1[0x23] == 0x77d) || (param_1[0x23] == 0x780)) {
        *(undefined *)(iVar9 + 0x30) = 3;
        FUN_80030334((double)FLOAT_803e2318,param_1,1,0);
        *(undefined **)(iVar9 + 0x34) = (&PTR_DAT_8030de7c)[param_1[0x23] * 8];
      }
      else {
        *(undefined *)(iVar9 + 0x30) = 0;
        FUN_80030334((double)FLOAT_803e22f8,param_1,0,0);
        *(undefined4 *)(iVar9 + 0x34) = *(undefined4 *)(&DAT_8030de70 + param_1[0x23] * 0x20);
      }
    }
    if (((*(char *)(iVar9 + 0x31) == DAT_803dd990) && (DAT_803dd991 != '\0')) &&
       ((cVar1 = *(char *)(iVar9 + 0x30), cVar1 != '\x01' &&
        ((cVar1 != '\x02' && (cVar1 != '\x05')))))) {
      *(undefined *)(iVar9 + 0x30) = 1;
      FUN_80030334((double)FLOAT_803e22f8,param_1,1,0);
      *(undefined4 *)(iVar9 + 0x34) = *(undefined4 *)(&DAT_8030de74 + param_1[0x23] * 0x20);
      if (param_1[0x23] == 0x77e) {
        FUN_8000b824(param_1,0x370);
        FUN_8000b824(param_1,0x36c);
        FUN_8000bb18(param_1,0x36d);
      }
    }
    sVar2 = param_1[0x23];
    if (sVar2 == 0x7a7) {
      uStack36 = (int)*param_1 ^ 0x80000000;
      local_28 = 0x43300000;
      iVar5 = (int)(FLOAT_803e2354 * FLOAT_803db414 +
                   (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e22e8));
      local_20 = (double)(longlong)iVar5;
      *param_1 = (short)iVar5;
    }
    else if (sVar2 != 0x78a) {
      local_2d = 0;
      if ((sVar2 == 0x77d) && (*(char *)(iVar9 + 0x30) == '\x02')) {
        if (FLOAT_803e2358 <= *(float *)(param_1 + 0x4c)) {
          dVar10 = (double)FLOAT_803dbc0c;
        }
        else {
          uVar6 = FUN_800221a0(0x32,0x96);
          local_20 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          FLOAT_803dbc0c = FLOAT_803e235c * (float)(local_20 - DOUBLE_803e22e8);
          dVar10 = (double)FLOAT_803dbc0c;
        }
      }
      else {
        dVar10 = (double)*(float *)(iVar9 + 0x34);
      }
      iVar5 = FUN_8002fa48(dVar10,(double)FLOAT_803db414,param_1,auStack72);
      if (iVar5 != 0) {
        if ((*(char *)(iVar9 + 0x31) == DAT_803dd990) && (*(char *)(iVar9 + 0x30) == '\x01')) {
          *(undefined *)(iVar9 + 0x30) = 2;
          FUN_80030334((double)FLOAT_803e22f8,param_1,2,0);
          *(undefined **)(iVar9 + 0x34) = (&PTR_DAT_8030de78)[param_1[0x23] * 8];
        }
        else if (*(char *)(iVar9 + 0x30) == '\x03') {
          *(undefined *)(iVar9 + 0x30) = 0;
          FUN_80030334((double)FLOAT_803e22f8,param_1,0,0);
          *(undefined4 *)(iVar9 + 0x34) = *(undefined4 *)(&DAT_8030de70 + param_1[0x23] * 0x20);
        }
        else if ((0x77c < param_1[0x23]) && (param_1[0x23] < 0x781)) {
          iVar5 = FUN_800221a0(0,4);
          if (iVar5 == 0) {
            if ((*(char *)(iVar9 + 0x30) == '\0') || (*(char *)(iVar9 + 0x30) == '\x04')) {
              *(undefined *)(iVar9 + 0x30) = 4;
              uVar3 = FUN_800221a0(3,4);
              FUN_80030334((double)FLOAT_803e22f8,param_1,uVar3,0);
              *(undefined4 *)(iVar9 + 0x34) =
                   *(undefined4 *)(&DAT_8030de74 + param_1[0x23] * 0x20 + param_1[0x50] * 4);
            }
            else {
              *(undefined *)(iVar9 + 0x30) = 5;
              uVar3 = FUN_800221a0(5,6);
              FUN_80030334((double)FLOAT_803e22f8,param_1,uVar3,0);
              *(undefined4 *)(iVar9 + 0x34) =
                   *(undefined4 *)(&DAT_8030de74 + param_1[0x23] * 0x20 + param_1[0x50] * 4);
            }
          }
          else if (*(char *)(iVar9 + 0x30) == '\x04') {
            *(undefined *)(iVar9 + 0x30) = 0;
            FUN_80030334((double)FLOAT_803e22f8,param_1,0,0);
            *(undefined4 *)(iVar9 + 0x34) = *(undefined4 *)(&DAT_8030de70 + param_1[0x23] * 0x20);
          }
          else if (*(char *)(iVar9 + 0x30) == '\x05') {
            *(undefined *)(iVar9 + 0x30) = 2;
            FUN_80030334((double)FLOAT_803e22f8,param_1,2,0);
            *(undefined **)(iVar9 + 0x34) = (&PTR_DAT_8030de78)[param_1[0x23] * 8];
          }
        }
      }
      FUN_80134870(param_1,auStack72);
    }
    sVar2 = param_1[0x23];
    if ((sVar2 == 0x77e) &&
       ((*(char *)(iVar9 + 0x30) == '\0' || (*(char *)(iVar9 + 0x30) == '\x04')))) {
      FUN_8003b228(param_1,iVar9);
    }
    else if ((0x77c < sVar2) && (sVar2 < 0x781)) {
      FUN_8003b310(param_1,iVar9);
    }
    piVar4 = (int *)FUN_8002b588(param_1);
    if (((*(char *)(*piVar4 + 0xf9) != '\0') && (iVar5 = FUN_800278e4(), iVar5 == 0)) &&
       (iVar5 = FUN_800221a0(0xf0,0x168), iVar5 == 0xf0)) {
      iVar7 = piVar4[10];
      iVar5 = FUN_800221a0(0,*(undefined *)(*piVar4 + 0xf9));
      FUN_800279cc((double)FLOAT_803e2360,piVar4,0,(int)*(char *)(iVar7 + 0xd),iVar5 + -1,0);
    }
    DAT_803dbc08 = 0xff;
    DAT_803dbc09 = 0xff;
    uVar6 = (uint)*(byte *)(iVar9 + 0x30);
    iVar9 = (int)param_1[0x23];
    if (iVar9 == 0x77f) {
      if (((uVar6 < 6) && (3 < uVar6)) && ((param_1[0x50] == 3 || (param_1[0x50] == 5)))) {
        iVar9 = uVar6 * 3;
        if (*(char *)(iVar9 + -0x7fc5608c) == '\0') {
          if (FLOAT_803e2368 < *(float *)(param_1 + 0x4c)) {
            FUN_8000bb18(param_1,0x421);
            *(undefined *)(iVar9 + -0x7fc5608c) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2368) {
          *(undefined *)(iVar9 + -0x7fc5608c) = 0;
        }
        pcVar8 = (char *)((param_1[0x23] + -0x77d) * 0x12 + iVar9 + -0x7fc560af);
        if (*pcVar8 == '\0') {
          if (FLOAT_803e236c < *(float *)(param_1 + 0x4c)) {
            FUN_8000bb18(param_1,0x421);
            *pcVar8 = '\x01';
          }
        }
        else if (*(float *)(param_1 + 0x4c) < FLOAT_803e236c) {
          *pcVar8 = '\0';
        }
      }
    }
    else if (iVar9 < 0x77f) {
      if (((iVar9 != 0x77d) && (0x77c < iVar9)) && (uVar6 == 5)) {
        iVar9 = (iVar9 + -0x77d) * 0x12;
        if (*(char *)(iVar9 + -0x7fc560a1) == '\0') {
          if (FLOAT_803e2364 < *(float *)(param_1 + 0x4c)) {
            FUN_8000bb18(param_1,0x41d);
            *(undefined *)(iVar9 + -0x7fc560a1) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2364) {
          *(undefined *)(iVar9 + -0x7fc560a1) = 0;
        }
      }
    }
    else if (iVar9 < 0x781) {
      if (uVar6 == 4) {
        iVar9 = (iVar9 + -0x77d) * 0x12;
        if (*(char *)(iVar9 + -0x7fc560a4) == '\0') {
          if (FLOAT_803e2370 < *(float *)(param_1 + 0x4c)) {
            FUN_8000bb18(param_1,0x414);
            *(undefined *)(iVar9 + -0x7fc560a4) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2370) {
          *(undefined *)(iVar9 + -0x7fc560a4) = 0;
        }
      }
      else if (uVar6 < 4) {
        if (uVar6 == 2) {
          iVar9 = (iVar9 + -0x77d) * 0x12;
          if (*(char *)(iVar9 + -0x7fc560aa) == '\0') {
            if (FLOAT_803e2368 < *(float *)(param_1 + 0x4c)) {
              FUN_8000bb18(param_1,0x426);
              *(undefined *)(iVar9 + -0x7fc560aa) = 1;
            }
          }
          else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2368) {
            *(undefined *)(iVar9 + -0x7fc560aa) = 0;
          }
          pcVar8 = (char *)((param_1[0x23] + -0x77d) * 0x12 + -0x7fc560a9);
          if (*pcVar8 == '\0') {
            if (FLOAT_803e2380 < *(float *)(param_1 + 0x4c)) {
              FUN_8000bb18(param_1,0x426);
              *pcVar8 = '\x01';
            }
          }
          else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2380) {
            *pcVar8 = '\0';
          }
          pcVar8 = (char *)((param_1[0x23] + -0x77d) * 0x12 + -0x7fc560a8);
          if (*pcVar8 == '\0') {
            if (FLOAT_803e2384 < *(float *)(param_1 + 0x4c)) {
              FUN_8000bb18(param_1,0x426);
              *pcVar8 = '\x01';
            }
          }
          else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2384) {
            *pcVar8 = '\0';
          }
        }
      }
      else if (uVar6 < 6) {
        iVar9 = (iVar9 + -0x77d) * 0x12 + -0x7fc560b0;
        iVar5 = uVar6 * 3;
        if (*(char *)(iVar9 + iVar5) == '\0') {
          if (FLOAT_803e2374 < *(float *)(param_1 + 0x4c)) {
            FUN_8000bb18(param_1,0x412);
            *(undefined *)(iVar9 + iVar5) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2374) {
          *(undefined *)(iVar9 + iVar5) = 0;
        }
        pcVar8 = (char *)((param_1[0x23] + -0x77d) * 0x12 + iVar5 + -0x7fc560af);
        if (*pcVar8 == '\0') {
          if (FLOAT_803e2378 < *(float *)(param_1 + 0x4c)) {
            FUN_8000bb18(param_1,0x426);
            *pcVar8 = '\x01';
          }
        }
        else if (*(float *)(param_1 + 0x4c) < FLOAT_803e2378) {
          *pcVar8 = '\0';
        }
        pcVar8 = (char *)((param_1[0x23] + -0x77d) * 0x12 + iVar5 + -0x7fc560ae);
        if (*pcVar8 == '\0') {
          if (FLOAT_803e237c < *(float *)(param_1 + 0x4c)) {
            FUN_8000bb18(param_1,0x413);
            *pcVar8 = '\x01';
          }
        }
        else if (*(float *)(param_1 + 0x4c) < FLOAT_803e237c) {
          *pcVar8 = '\0';
        }
      }
    }
    if (DAT_803dd992 == '\0') {
      FUN_80008cbc(0,0,0x21f,0);
      FUN_80089710(7,1,0);
      FUN_800895e0(7,0x4b,100,0x78,0,0);
      FUN_800894a8((double)FLOAT_803e2318,(double)FLOAT_803e2388,(double)FLOAT_803e2388,7);
      (**(code **)(*DAT_803dca50 + 0x28))(param_1,0);
      DAT_803dd992 = '\x01';
      FUN_80131f0c();
    }
  }
  return;
}

