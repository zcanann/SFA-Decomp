// Function: FUN_801b8344
// Entry: 801b8344
// Size: 1344 bytes

void FUN_801b8344(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)

{
  byte bVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  int *piVar8;
  float *pfVar9;
  float *pfVar10;
  int iVar11;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar12;
  undefined8 extraout_f1;
  double dVar13;
  undefined8 uVar14;
  int local_40;
  int local_3c;
  int local_38;
  undefined auStack_34 [12];
  int local_28;
  int local_24;
  int local_20;
  
  pfVar12 = (float *)param_9[0x2e];
  bVar1 = *(byte *)(pfVar12 + 0x2b);
  if ((bVar1 & 4) == 0) {
    if ((bVar1 & 8) != 0) {
      iVar11 = (uint)*(byte *)((int)param_9 + 0x36) + (uint)DAT_803dc070 * -2;
      if (iVar11 < 0) {
        iVar11 = 0;
        *(byte *)(pfVar12 + 0x2b) = bVar1 & 0xf7;
      }
      *(char *)((int)param_9 + 0x36) = (char)iVar11;
    }
  }
  else {
    uVar5 = (uint)*(byte *)((int)param_9 + 0x36) + (uint)DAT_803dc070 * 2;
    if (0xff < uVar5) {
      uVar5 = 0xff;
      *(byte *)(pfVar12 + 0x2b) = bVar1 & 0xfb;
    }
    *(char *)((int)param_9 + 0x36) = (char)uVar5;
  }
  if ((*(byte *)(pfVar12 + 0x2b) & 1) == 0) {
    pfVar7 = pfVar12 + 0x22;
    pfVar9 = pfVar12 + 0x23;
    pfVar10 = pfVar12 + 0x2a;
    iVar11 = **(int **)((int)pfVar12[0x27] + 0x68);
    uVar14 = (**(code **)(iVar11 + 0x20))(pfVar12[0x27],pfVar12 + 0x21);
    pfVar12[0x24] = (float)((ulonglong)uVar14 >> 0x20);
    pfVar12[0x20] = 0.0;
    pfVar12[0x25] = (float)FUN_80010de0;
    pfVar12[0x26] = (float)&LAB_80010d74;
    FUN_80010a8c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,pfVar12,
                 (int)uVar14,pfVar7,pfVar9,pfVar10,iVar11,in_r9,in_r10);
    *(byte *)(pfVar12 + 0x2b) = *(byte *)(pfVar12 + 0x2b) | 1;
  }
  fVar4 = FLOAT_803e5748;
  fVar3 = FLOAT_803e573c;
  if ((*(byte *)(pfVar12 + 0x2b) & 2) == 0) {
    iVar11 = FUN_80010340((double)FLOAT_803e5758,pfVar12);
    param_9[3] = (int)pfVar12[0x1a];
    param_9[4] = (int)(float)(DOUBLE_803e5760 + (double)pfVar12[0x1b]);
    param_9[5] = (int)pfVar12[0x1c];
    iVar6 = FUN_80021884();
    *(short *)param_9 = (short)iVar6;
    *(ushort *)((int)param_9 + 2) = *(short *)((int)param_9 + 2) + (ushort)DAT_803dc070 * 800;
    param_9[9] = (int)(FLOAT_803dc078 * ((float)param_9[3] - (float)param_9[0x20]));
    param_9[10] = (int)FLOAT_803e5768;
    dVar13 = (double)FLOAT_803dc078;
    param_9[0xb] = (int)(float)(dVar13 * (double)(float)((double)(float)param_9[5] -
                                                        (double)(float)param_9[0x22]));
    if (iVar11 != 0) {
      FUN_8002cc9c((double)(float)param_9[5],dVar13,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9);
      return;
    }
    if ((*(char *)((int)pfVar12[0x2a] + ((int)pfVar12[4] >> 2)) == ' ') &&
       (uVar5 = FUN_80020078(0x288), uVar5 != 0)) {
      *(byte *)(pfVar12 + 0x2b) = *(byte *)(pfVar12 + 0x2b) | 2;
      iVar11 = FUN_80065fcc((double)(float)param_9[3],(double)(float)param_9[4],
                            (double)(float)param_9[5],param_9,&local_38,0,0);
      pfVar12[0x29] = (float)param_9[4];
      while (fVar3 = FLOAT_803e5754, 0 < iVar11) {
        iVar11 = iVar11 + -1;
        pfVar7 = *(float **)(local_38 + iVar11 * 4);
        fVar3 = *pfVar7;
        if ((fVar3 < (float)param_9[4]) &&
           ((cVar2 = *(char *)(pfVar7 + 5), cVar2 == '\x1a' || (cVar2 == '\b')))) {
          pfVar12[0x29] = fVar3;
          iVar11 = 0;
        }
      }
      param_9[9] = (int)((float)param_9[9] * FLOAT_803e5754);
      param_9[0xb] = (int)((float)param_9[0xb] * fVar3);
    }
  }
  else if (pfVar12[0x29] <= (float)param_9[4]) {
    param_9[9] = (int)((float)param_9[9] * FLOAT_803e5748);
    param_9[10] = (int)-(FLOAT_803e574c * FLOAT_803dc074 - (float)param_9[10]);
    param_9[0xb] = (int)((float)param_9[0xb] * fVar4);
    FUN_8002ba34((double)((float)param_9[9] * FLOAT_803dc074),
                 (double)((float)param_9[10] * FLOAT_803dc074),
                 (double)((float)param_9[0xb] * FLOAT_803dc074),(int)param_9);
    iVar11 = FUN_80064248(param_9 + 0x20,param_9 + 3,(float *)0x0,(int *)0x0,param_9,8,0xffffffff,0,
                          0);
    if (iVar11 != 0) {
      param_9[9] = (int)-(float)param_9[9];
      param_9[0xb] = (int)-(float)param_9[0xb];
      fVar3 = FLOAT_803e5754;
      param_9[9] = (int)((float)param_9[9] * FLOAT_803e5754);
      param_9[0xb] = (int)((float)param_9[0xb] * fVar3);
    }
  }
  else {
    param_9[9] = (int)((float)param_9[9] * FLOAT_803e573c);
    param_9[10] = (int)FLOAT_803e5740;
    param_9[0xb] = (int)((float)param_9[0xb] * fVar3);
    fVar3 = FLOAT_803e5744;
    if ((*(byte *)(pfVar12 + 0x2b) & 0x10) == 0) {
      param_9[9] = (int)((float)param_9[9] * FLOAT_803e5744);
      param_9[0xb] = (int)((float)param_9[0xb] * fVar3);
      *(byte *)(pfVar12 + 0x2b) = *(byte *)(pfVar12 + 0x2b) | 0x18;
      iVar11 = FUN_8002e1f4(&local_40,&local_3c);
      piVar8 = (int *)(iVar11 + local_40 * 4);
      for (; local_40 < local_3c; local_40 = local_40 + 1) {
        if (*(short *)(*piVar8 + 0x46) == 0xd6) {
          iVar11 = *(int *)(iVar11 + local_40 * 4);
          goto LAB_801b8534;
        }
        piVar8 = piVar8 + 1;
      }
      iVar11 = 0;
LAB_801b8534:
      if (iVar11 != 0) {
        (**(code **)(**(int **)(iVar11 + 0x68) + 0x20))();
      }
      FUN_8000bb38((uint)param_9,0x1fa);
    }
    local_28 = param_9[3];
    local_24 = param_9[4];
    local_20 = param_9[5];
    uVar14 = (**(code **)(*DAT_803dd708 + 8))(param_9,0x206,auStack_34,4,0xffffffff,0);
    if (*(char *)((int)param_9 + 0x36) == '\0') {
      FUN_8002cc9c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
    FUN_8002ba34((double)((float)param_9[9] * FLOAT_803dc074),
                 (double)((float)param_9[10] * FLOAT_803dc074),
                 (double)((float)param_9[0xb] * FLOAT_803dc074),(int)param_9);
  }
  if ((*(char *)((int)param_9 + 0x36) == -1) && (iVar11 = param_9[0x15], iVar11 != 0)) {
    *(ushort *)(iVar11 + 0x60) = *(ushort *)(iVar11 + 0x60) | 1;
    *(undefined *)(iVar11 + 0x6e) = 4;
    *(undefined *)(iVar11 + 0x6f) = 2;
    *(undefined4 *)(iVar11 + 0x48) = 0x10;
    *(undefined4 *)(iVar11 + 0x4c) = 0x10;
  }
  FUN_8000da78((uint)param_9,0x493);
  return;
}

