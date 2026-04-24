// Function: FUN_801db998
// Entry: 801db998
// Size: 2728 bytes

void FUN_801db998(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)

{
  float fVar1;
  int iVar2;
  char cVar5;
  uint uVar3;
  int iVar4;
  byte bVar6;
  undefined4 uVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar8;
  undefined8 uVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double dVar10;
  
  pfVar8 = *(float **)(param_9 + 0xb8);
  iVar2 = FUN_8002bac4();
  if (*(int *)(param_9 + 0xf4) != 0) {
    uVar9 = FUN_80088f20(7,'\0');
    uVar9 = FUN_80088a84(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    if (*(int *)(param_9 + 0xf4) == 2) {
      uVar9 = FUN_80008b74(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x4f,0,
                           in_r7,in_r8,in_r9,in_r10);
      uVar9 = FUN_80008b74(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x50,0,
                           in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x245,0,in_r7,
                   in_r8,in_r9,in_r10);
      cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,5);
      if (cVar5 == '\0') {
        FUN_80008b74(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x51,0,
                     in_r7,in_r8,in_r9,in_r10);
      }
      else {
        FUN_80008b74(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x246,0
                     ,in_r7,in_r8,in_r9,in_r10);
      }
    }
    else {
      uVar9 = FUN_80008cbc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x4f,0,
                           in_r7,in_r8,in_r9,in_r10);
      uVar9 = FUN_80008cbc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x50,0,
                           in_r7,in_r8,in_r9,in_r10);
      FUN_80008cbc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x245,0,in_r7,
                   in_r8,in_r9,in_r10);
      cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,5);
      if (cVar5 == '\0') {
        FUN_80008cbc(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x51
                     ,0,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        FUN_80008cbc(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                     0x246,0,in_r7,in_r8,in_r9,in_r10);
      }
    }
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  if ((-1 < *(char *)((int)pfVar8 + 0x22)) && (uVar3 = FUN_80020078(0xc53), uVar3 != 0)) {
    (**(code **)(*DAT_803dd72c + 0x50))(0xe,10,1);
    *(byte *)((int)pfVar8 + 0x22) = *(byte *)((int)pfVar8 + 0x22) & 0x7f | 0x80;
  }
  if (*(char *)((int)pfVar8 + 0x1e) != '\x0e') {
    iVar4 = FUN_8005b128();
    if (iVar4 != 0xe) {
      return;
    }
    bVar6 = (**(code **)(*DAT_803dd72c + 0x40))(0xe);
    FUN_8002bac4();
    if (bVar6 == 1) {
      uVar3 = FUN_80020078(0x5f3);
      if (uVar3 != 0) {
        (**(code **)(*DAT_803dd72c + 0x44))(0xe,2);
      }
    }
    else if (((bVar6 != 0) && (bVar6 < 6)) && (uVar3 = FUN_80020078(0x2d0), uVar3 != 0)) {
      (**(code **)(*DAT_803dd72c + 0x44))(0xe,6);
    }
  }
  if ((pfVar8[5] == FLOAT_803e61f0) || ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)) {
    if ((pfVar8[4] != FLOAT_803e61f0) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
      if (FLOAT_803e61e8 == pfVar8[4]) {
        (**(code **)(*DAT_803dd6cc + 8))(0x73,1);
      }
      pfVar8[4] = pfVar8[4] - FLOAT_803dc074;
      if (pfVar8[4] <= FLOAT_803e61f0) {
        FUN_800201ac(0x640,1);
        pfVar8[4] = FLOAT_803e61f0;
        FUN_800201ac(0x2b8,0);
        FUN_800201ac(0x4bd,1);
        FUN_800201ac(0x81,0);
        FUN_800201ac(0x82,0);
        FUN_800201ac(0x83,0);
        FUN_800201ac(0x84,0);
      }
    }
  }
  else {
    if (FLOAT_803e61e8 == pfVar8[5]) {
      (**(code **)(*DAT_803dd6cc + 8))(0x73,1);
    }
    pfVar8[5] = pfVar8[5] - FLOAT_803dc074;
    fVar1 = FLOAT_803e61f0;
    if (pfVar8[5] <= FLOAT_803e61f0) {
      pfVar8[5] = FLOAT_803e61f0;
      pfVar8[4] = fVar1;
      FUN_800201ac(0x2b8,0);
      FUN_800201ac(0x4bd,1);
      FUN_800201ac(0x81,0);
      FUN_800201ac(0x82,0);
      FUN_800201ac(0x83,0);
      FUN_800201ac(0x84,0);
      FUN_800201ac(0x63e,1);
      FUN_800201ac(1999,1);
    }
  }
  dVar10 = (double)*(float *)(iVar2 + 0x14);
  iVar2 = FUN_8005b128();
  *(char *)((int)pfVar8 + 0x1e) = (char)iVar2;
  uVar3 = FUN_80020078(0xcdc);
  if (uVar3 == 0) {
    pfVar8[1] = FLOAT_803e6204;
    pfVar8[2] = FLOAT_803e6200;
  }
  else {
    if ((double)FLOAT_803e61f0 < (double)pfVar8[3]) {
      FUN_800168a8((double)pfVar8[3],dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x429);
      pfVar8[3] = pfVar8[3] - FLOAT_803dc074;
      if (pfVar8[3] < FLOAT_803e61f0) {
        pfVar8[3] = FLOAT_803e61f0;
      }
    }
    cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,1);
    if (cVar5 == '\0') {
      cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))(0xe,5);
      if (cVar5 == '\0') {
        pfVar8[1] = FLOAT_803e61f4;
        pfVar8[2] = FLOAT_803e61f8;
      }
      else {
        pfVar8[1] = FLOAT_803e61fc;
        pfVar8[2] = FLOAT_803e6200;
        if (*(int *)(param_9 + 0xf8) != 0) {
          FUN_800890e0((double)FLOAT_803e61ec,1);
          *(undefined4 *)(param_9 + 0xf8) = 0;
        }
      }
    }
    else {
      pfVar8[1] = FLOAT_803e61f4;
      pfVar8[2] = FLOAT_803e61f8;
    }
  }
  dVar10 = (double)*pfVar8;
  if ((double)pfVar8[1] != dVar10) {
    *pfVar8 = (float)((double)pfVar8[2] * (double)FLOAT_803dc074 + dVar10);
    if (FLOAT_803e61f0 <= pfVar8[2]) {
      if (pfVar8[1] < *pfVar8) {
        *pfVar8 = pfVar8[1];
      }
    }
    else if (*pfVar8 < pfVar8[1]) {
      *pfVar8 = pfVar8[1];
    }
    dVar10 = (double)*pfVar8;
    param_3 = (double)FLOAT_803e620c;
    param_4 = (double)FLOAT_803e6210;
    param_5 = (double)FLOAT_803e6214;
    FUN_8004c38c((double)(float)((double)FLOAT_803e6208 + dVar10),dVar10,param_3,param_4,param_5,0);
  }
  uVar3 = FUN_80020078(0x7d);
  if (uVar3 == 0) {
    uVar3 = FUN_80020078(0x7e);
    if (uVar3 == 0) {
      uVar3 = FUN_80020078(0x7f);
      if (uVar3 != 0) {
        FUN_800201ac(0x7f,0);
        if (*(short *)(&DAT_803dccc8 + (uint)*(byte *)(pfVar8 + 7) * 2) == 0x7f) {
          *(byte *)(pfVar8 + 7) = *(byte *)(pfVar8 + 7) + 1;
        }
        else {
          *(undefined *)(pfVar8 + 7) = 0;
        }
      }
    }
    else {
      FUN_800201ac(0x7e,0);
      if (*(short *)(&DAT_803dccc8 + (uint)*(byte *)(pfVar8 + 7) * 2) == 0x7e) {
        *(byte *)(pfVar8 + 7) = *(byte *)(pfVar8 + 7) + 1;
      }
      else {
        *(undefined *)(pfVar8 + 7) = 0;
      }
    }
  }
  else {
    FUN_800201ac(0x7d,0);
    if (*(short *)(&DAT_803dccc8 + (uint)*(byte *)(pfVar8 + 7) * 2) == 0x7d) {
      *(byte *)(pfVar8 + 7) = *(byte *)(pfVar8 + 7) + 1;
    }
    else {
      *(undefined *)(pfVar8 + 7) = 0;
    }
  }
  if (2 < *(byte *)(pfVar8 + 7)) {
    FUN_800201ac(0x80,1);
    *(undefined *)(pfVar8 + 7) = 0;
  }
  if ((*(byte *)((int)pfVar8 + 0x1f) & 1) != 0) {
    *(byte *)((int)pfVar8 + 0x1f) = *(byte *)((int)pfVar8 + 0x1f) & 0xfe;
    FUN_800201ac(0x60f,1);
    uVar3 = FUN_80020078(0x7a);
    if (uVar3 == 0) {
      uVar3 = FUN_80020078(0x627);
      if ((uVar3 != 0) && (uVar3 = FUN_80020078(0x63e), uVar3 != 0)) {
        FUN_800201ac(0x61c,1);
      }
    }
    else {
      uVar3 = FUN_80020078(0x61c);
      if (uVar3 != 0) {
        FUN_800201ac(0x85,1);
      }
    }
  }
  if (*(char *)((int)pfVar8 + 0x1d) == '\0') {
    uVar3 = FUN_80020078(0x60e);
    if (uVar3 != 0) {
      FUN_800201ac(0x60e,0);
      FUN_8012e250();
    }
  }
  else if ((*(char *)((int)pfVar8 + 0x1d) == '\x05') && (uVar3 = FUN_80020078(0x60e), uVar3 != 0)) {
    FUN_800201ac(0x60e,0);
    FUN_800146a8();
    uVar3 = FUN_80020078(0x7a);
    if (uVar3 != 0) {
      FUN_800201ac(0x85,1);
    }
    pfVar8[4] = FLOAT_803e61e8;
    (**(code **)(*DAT_803dd6cc + 8))(0x73,1);
    *(undefined *)((int)pfVar8 + 0x1d) = 0;
    FUN_8000bb38(0,0x10a);
  }
  uVar3 = FUN_80020078(0x647);
  if (uVar3 != 0) {
    FUN_800201ac(0x612,1);
    FUN_800201ac(0x90b,1);
    FUN_800201ac(0x87,1);
  }
  uVar3 = FUN_80020078(0xbde);
  if (uVar3 != 0) {
    FUN_800201ac(0x2c6,1);
    FUN_800201ac(0x2ce,1);
    FUN_800201ac(0xbdc,1);
  }
  uVar3 = FUN_80020078(0xbe5);
  if (uVar3 != 0) {
    FUN_800201ac(0xbdf,1);
    FUN_800201ac(0xbe1,1);
    FUN_800201ac(0xbe3,1);
  }
  iVar2 = *(int *)(param_9 + 0xb8);
  FUN_8002bac4();
  if (*(char *)(iVar2 + 0x1d) == '\x05') {
    FUN_800201ac(0x60f,1);
    bVar6 = FUN_8001469c();
    if (bVar6 != 0) {
      uVar3 = FUN_80020078(0x7a);
      if (uVar3 != 0) {
        FUN_800201ac(0x85,1);
      }
      *(float *)(iVar2 + 0x10) = FLOAT_803e61e8;
      *(undefined *)(iVar2 + 0x1d) = 0;
      FUN_8000bb38(0,0x10a);
      FUN_8000a538((int *)0xef,0);
    }
  }
  uVar3 = FUN_80020078(0x4d0);
  if ((uVar3 == 0) && (uVar3 = FUN_80020078(0x2b5), uVar3 != 0)) {
    FUN_800201ac(0x4d0,1);
    uVar7 = 1;
    iVar2 = *DAT_803dd72c;
    uVar9 = (**(code **)(iVar2 + 0x50))(0xe,2);
    FUN_80055464(uVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,0x50,'\0',uVar7,iVar2,
                 in_r7,in_r8,in_r9,in_r10);
    (**(code **)(*DAT_803dd72c + 0x50))(0xe,1,0);
  }
  iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar2 == 0) {
    if (*(char *)(pfVar8 + 8) != '3') {
      *(undefined *)(pfVar8 + 8) = 0x33;
      FUN_8000a538((int *)0x33,1);
    }
    if (*(char *)((int)pfVar8 + 0x21) != '\"') {
      *(undefined *)((int)pfVar8 + 0x21) = 0x22;
      FUN_8000a538((int *)0x22,1);
    }
  }
  else {
    if (*(char *)(pfVar8 + 8) != '-') {
      *(undefined *)(pfVar8 + 8) = 0x2d;
      FUN_8000a538((int *)0x2d,1);
    }
    if (*(char *)((int)pfVar8 + 0x21) != -1) {
      *(undefined *)((int)pfVar8 + 0x21) = 0xff;
      FUN_8000a538((int *)0x22,0);
    }
  }
  FUN_801d84c4(pfVar8 + 6,1,-1,-1,0xe1e,(int *)0x36);
  FUN_801d84c4(pfVar8 + 6,2,-1,-1,0xcbb,(int *)0xc4);
  if ((*(byte *)((int)pfVar8 + 0x1f) & 2) != 0) {
    FUN_800201ac(0x60e,1);
    *(byte *)((int)pfVar8 + 0x1f) = *(byte *)((int)pfVar8 + 0x1f) & 0xfd;
  }
  return;
}

