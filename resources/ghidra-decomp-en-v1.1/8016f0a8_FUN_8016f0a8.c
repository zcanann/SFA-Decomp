// Function: FUN_8016f0a8
// Entry: 8016f0a8
// Size: 756 bytes

void FUN_8016f0a8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  undefined8 local_18;
  
  piVar6 = *(int **)(param_9 + 0xb8);
  iVar2 = FUN_8002b660(param_9);
  *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
  FUN_8002fb40((double)(float)piVar6[0x14],(double)FLOAT_803dc074);
  iVar2 = 3;
  piVar3 = piVar6;
  do {
    if ((*(byte *)(piVar3 + 5) & 2) != 0) {
      uVar4 = (uint)*(ushort *)(piVar3 + 3);
      iVar5 = *piVar3 + uVar4 * 0x14;
      for (; (int)uVar4 < (int)(uint)*(ushort *)((int)piVar3 + 0xe); uVar4 = uVar4 + 2) {
        if (piVar3 == (int *)piVar6[0x12]) {
          param_3 = (double)FLOAT_803e3f8c;
          dVar7 = (double)(float)(param_3 *
                                 (double)((FLOAT_803e3fa4 * (float)piVar6[0x26] -
                                          *(float *)(iVar5 + 0xc)) * FLOAT_803e3fa8));
          dVar8 = (double)FLOAT_803e3f4c;
          if ((dVar8 <= dVar7) && (dVar8 = dVar7, param_3 < dVar7)) {
            dVar8 = param_3;
          }
          *(short *)(iVar5 + 0x10) = (short)(int)(param_3 - dVar8);
          *(undefined2 *)(iVar5 + 0x24) = *(undefined2 *)(iVar5 + 0x10);
        }
        else {
          param_3 = (double)FLOAT_803e3fc4;
          local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x10) ^ 0x80000000);
          *(short *)(iVar5 + 0x10) =
               (short)(int)-(float)(param_3 * (double)FLOAT_803dc074 -
                                   (double)(float)(local_18 - DOUBLE_803e3fb0));
          *(undefined2 *)(iVar5 + 0x24) = *(undefined2 *)(iVar5 + 0x10);
        }
        sVar1 = *(short *)(iVar5 + 0x10);
        if (sVar1 < 0) {
          sVar1 = 0;
        }
        else if (0xff < sVar1) {
          sVar1 = 0xff;
        }
        *(short *)(iVar5 + 0x10) = sVar1;
        sVar1 = *(short *)(iVar5 + 0x24);
        if (sVar1 < 0) {
          sVar1 = 0;
        }
        else if (0xff < sVar1) {
          sVar1 = 0xff;
        }
        *(short *)(iVar5 + 0x24) = sVar1;
        if ((*(short *)(iVar5 + 0x10) < 1) && (*(short *)(iVar5 + 0x24) < 1)) {
          *(short *)((int)piVar3 + 0x12) = *(short *)((int)piVar3 + 0x12) + -2;
          *(short *)(piVar3 + 3) = *(short *)(piVar3 + 3) + 2;
        }
        iVar5 = iVar5 + 0x28;
      }
      if ((piVar3 != (int *)piVar6[0x12]) && (*(short *)((int)piVar3 + 0x12) == 0)) {
        *(byte *)(piVar3 + 5) = *(byte *)(piVar3 + 5) & 0xfd;
      }
    }
    piVar3 = piVar3 + 6;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  FUN_8016d394(param_9,*(int *)(param_9 + 0xc4));
  FUN_80297300(*(int *)(param_9 + 0xc4));
  *(undefined *)((int)piVar6 + 0xb9) = 0;
  if (DAT_803ad338 != '\0') {
    DAT_803ad324 = DAT_803ad324 + FLOAT_803e3f78;
    FUN_80035a6c(DAT_803ad334,(short)(int)DAT_803ad324);
    FUN_80035eec(DAT_803ad334,0x11,5,0);
    DAT_803ad330 = DAT_803ad330 + FLOAT_803e3f7c;
    dVar8 = (double)DAT_803ad330;
    DAT_803ad328 = DAT_803ad328 * FLOAT_803e3f80;
    DAT_803ad32c = DAT_803ad32c * FLOAT_803e3f84;
    *(char *)(DAT_803ad334 + 0x36) = (char)(int)DAT_803ad330;
    *(float *)(DAT_803ad334 + 8) = *(float *)(DAT_803ad334 + 8) + FLOAT_803e3f88;
    if ((double)DAT_803ad330 < (double)FLOAT_803e3f20) {
      DAT_803ad338 = '\0';
      FUN_8002cc9c((double)DAT_803ad330,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                   DAT_803ad334);
      DAT_803ad334 = 0;
    }
  }
  return;
}

