// Function: FUN_8005c7ec
// Entry: 8005c7ec
// Size: 608 bytes

void FUN_8005c7ec(int param_1)

{
  float fVar1;
  int iVar2;
  int *piVar3;
  float *pfVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  if (param_1 == 0) {
    FUN_80088884();
    (**(code **)(*DAT_803dca64 + 0xc))();
    (**(code **)(*DAT_803dca5c + 0xc))();
    (**(code **)(*DAT_803dca58 + 0xc))();
    iVar2 = (**(code **)(*DAT_803dca60 + 0x10))();
    iVar6 = 0;
    iVar5 = 0;
    do {
      piVar3 = (int *)(DAT_803dce6c + iVar5);
      if ((((*(short *)(piVar3 + 3) != 0) && (iVar2 = *piVar3, iVar2 != 0)) &&
          (*(short *)(iVar2 + 0x10) != 0x100)) && (*(short *)(iVar2 + 0x14) != 0)) {
        iVar2 = FUN_80053f2c(iVar2,piVar3 + 2,piVar3 + 1);
      }
      iVar5 = iVar5 + 0x10;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x50);
    iVar5 = 0;
    iVar6 = 0;
    iVar7 = 0x1d;
    do {
      pfVar4 = (float *)(DAT_803dce68 + iVar6);
      if (*(char *)(pfVar4 + 3) != '\0') {
        iVar2 = 0x43300000;
        fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)((int)pfVar4 + 10) ^ 0x80000000)
                       - DOUBLE_803debc0) * FLOAT_803db414;
        *pfVar4 = *pfVar4 + (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(pfVar4 + 2) ^ 0x80000000) -
                                   DOUBLE_803debc0) * FLOAT_803db414;
        pfVar4[1] = pfVar4[1] + fVar1;
      }
      pfVar4 = (float *)(DAT_803dce68 + iVar6 + 0x10);
      if (*(char *)(pfVar4 + 3) != '\0') {
        iVar2 = 0x43300000;
        fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)((int)pfVar4 + 10) ^ 0x80000000)
                       - DOUBLE_803debc0) * FLOAT_803db414;
        *pfVar4 = *pfVar4 + (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(pfVar4 + 2) ^ 0x80000000) -
                                   DOUBLE_803debc0) * FLOAT_803db414;
        pfVar4[1] = pfVar4[1] + fVar1;
      }
      iVar6 = iVar6 + 0x20;
      iVar5 = iVar5 + 1;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    FUN_80055130(iVar2,iVar5);
    if (DAT_803dcab0 != (int *)0x0) {
      (**(code **)(*DAT_803dcab0 + 8))();
    }
    (**(code **)(*DAT_803dcabc + 4))();
    if (DAT_803dce00 != 0) {
      DAT_803dcdfc = DAT_803dcdfc + DAT_803dce00;
      if (DAT_803dcdfc < 0) {
        DAT_803dcdfc = 0;
        DAT_803dce00 = 0;
      }
      else if (0xff < DAT_803dcdfc) {
        DAT_803dcdfc = 0xff;
        DAT_803dce00 = 0;
      }
    }
  }
  return;
}

