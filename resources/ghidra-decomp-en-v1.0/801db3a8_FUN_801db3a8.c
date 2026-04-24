// Function: FUN_801db3a8
// Entry: 801db3a8
// Size: 2728 bytes

void FUN_801db3a8(int param_1)

{
  float fVar1;
  int iVar2;
  char cVar4;
  int iVar3;
  byte bVar5;
  undefined uVar6;
  float *pfVar7;
  
  pfVar7 = *(float **)(param_1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  if (*(int *)(param_1 + 0xf4) != 0) {
    FUN_80088c94(7,0);
    FUN_800887f8(0);
    if (*(int *)(param_1 + 0xf4) == 2) {
      FUN_80008b74(0,0,0x4f,0);
      FUN_80008b74(0,0,0x50,0);
      FUN_80008b74(0,0,0x245,0);
      cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))(0xe,5);
      if (cVar4 == '\0') {
        FUN_80008b74(0,0,0x51,0);
      }
      else {
        FUN_80008b74(0,0,0x246,0);
      }
    }
    else {
      FUN_80008cbc(0,0,0x4f,0);
      FUN_80008cbc(0,0,0x50,0);
      FUN_80008cbc(0,0,0x245,0);
      cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))(0xe,5);
      if (cVar4 == '\0') {
        FUN_80008cbc(0,0,0x51,0);
      }
      else {
        FUN_80008cbc(0,0,0x246,0);
      }
    }
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  if ((-1 < *(char *)((int)pfVar7 + 0x22)) && (iVar3 = FUN_8001ffb4(0xc53), iVar3 != 0)) {
    (**(code **)(*DAT_803dcaac + 0x50))(0xe,10,1);
    *(byte *)((int)pfVar7 + 0x22) = *(byte *)((int)pfVar7 + 0x22) & 0x7f | 0x80;
  }
  if (*(char *)((int)pfVar7 + 0x1e) != '\x0e') {
    iVar3 = FUN_8005afac((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x14));
    if (iVar3 != 0xe) {
      return;
    }
    bVar5 = (**(code **)(*DAT_803dcaac + 0x40))(0xe);
    FUN_8002b9ec();
    if (bVar5 == 1) {
      iVar3 = FUN_8001ffb4(0x5f3);
      if (iVar3 != 0) {
        (**(code **)(*DAT_803dcaac + 0x44))(0xe,2);
      }
    }
    else if (((bVar5 != 0) && (bVar5 < 6)) && (iVar3 = FUN_8001ffb4(0x2d0), iVar3 != 0)) {
      (**(code **)(*DAT_803dcaac + 0x44))(0xe,6);
    }
  }
  if ((pfVar7[5] == FLOAT_803e5558) || ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)) {
    if ((pfVar7[4] != FLOAT_803e5558) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
      if (FLOAT_803e5550 == pfVar7[4]) {
        (**(code **)(*DAT_803dca4c + 8))(0x73,1);
      }
      pfVar7[4] = pfVar7[4] - FLOAT_803db414;
      if (pfVar7[4] <= FLOAT_803e5558) {
        FUN_800200e8(0x640,1);
        pfVar7[4] = FLOAT_803e5558;
        FUN_800200e8(0x2b8,0);
        FUN_800200e8(0x4bd,1);
        FUN_800200e8(0x81,0);
        FUN_800200e8(0x82,0);
        FUN_800200e8(0x83,0);
        FUN_800200e8(0x84,0);
      }
    }
  }
  else {
    if (FLOAT_803e5550 == pfVar7[5]) {
      (**(code **)(*DAT_803dca4c + 8))(0x73,1);
    }
    pfVar7[5] = pfVar7[5] - FLOAT_803db414;
    fVar1 = FLOAT_803e5558;
    if (pfVar7[5] <= FLOAT_803e5558) {
      pfVar7[5] = FLOAT_803e5558;
      pfVar7[4] = fVar1;
      FUN_800200e8(0x2b8,0);
      FUN_800200e8(0x4bd,1);
      FUN_800200e8(0x81,0);
      FUN_800200e8(0x82,0);
      FUN_800200e8(0x83,0);
      FUN_800200e8(0x84,0);
      FUN_800200e8(0x63e,1);
      FUN_800200e8(1999,1);
    }
  }
  uVar6 = FUN_8005afac((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x14));
  *(undefined *)((int)pfVar7 + 0x1e) = uVar6;
  iVar2 = FUN_8001ffb4(0xcdc);
  if (iVar2 == 0) {
    pfVar7[1] = FLOAT_803e556c;
    pfVar7[2] = FLOAT_803e5568;
  }
  else {
    if (FLOAT_803e5558 < pfVar7[3]) {
      FUN_80016870(0x429);
      pfVar7[3] = pfVar7[3] - FLOAT_803db414;
      if (pfVar7[3] < FLOAT_803e5558) {
        pfVar7[3] = FLOAT_803e5558;
      }
    }
    cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))(0xe,1);
    if (cVar4 == '\0') {
      cVar4 = (**(code **)(*DAT_803dcaac + 0x4c))(0xe,5);
      if (cVar4 == '\0') {
        pfVar7[1] = FLOAT_803e555c;
        pfVar7[2] = FLOAT_803e5560;
      }
      else {
        pfVar7[1] = FLOAT_803e5564;
        pfVar7[2] = FLOAT_803e5568;
        if (*(int *)(param_1 + 0xf8) != 0) {
          FUN_80088e54((double)FLOAT_803e5554,1);
          *(undefined4 *)(param_1 + 0xf8) = 0;
        }
      }
    }
    else {
      pfVar7[1] = FLOAT_803e555c;
      pfVar7[2] = FLOAT_803e5560;
    }
  }
  if (pfVar7[1] != *pfVar7) {
    *pfVar7 = pfVar7[2] * FLOAT_803db414 + *pfVar7;
    if (FLOAT_803e5558 <= pfVar7[2]) {
      if (pfVar7[1] < *pfVar7) {
        *pfVar7 = pfVar7[1];
      }
    }
    else if (*pfVar7 < pfVar7[1]) {
      *pfVar7 = pfVar7[1];
    }
    FUN_8004c210((double)(float)((double)FLOAT_803e5570 + (double)*pfVar7),(double)*pfVar7,
                 (double)FLOAT_803e5574,(double)FLOAT_803e5578,(double)FLOAT_803e557c,0);
  }
  iVar2 = FUN_8001ffb4(0x7d);
  if (iVar2 == 0) {
    iVar2 = FUN_8001ffb4(0x7e);
    if (iVar2 == 0) {
      iVar2 = FUN_8001ffb4(0x7f);
      if (iVar2 != 0) {
        FUN_800200e8(0x7f,0);
        if (*(short *)(&DAT_803dc060 + (uint)*(byte *)(pfVar7 + 7) * 2) == 0x7f) {
          *(byte *)(pfVar7 + 7) = *(byte *)(pfVar7 + 7) + 1;
        }
        else {
          *(undefined *)(pfVar7 + 7) = 0;
        }
      }
    }
    else {
      FUN_800200e8(0x7e,0);
      if (*(short *)(&DAT_803dc060 + (uint)*(byte *)(pfVar7 + 7) * 2) == 0x7e) {
        *(byte *)(pfVar7 + 7) = *(byte *)(pfVar7 + 7) + 1;
      }
      else {
        *(undefined *)(pfVar7 + 7) = 0;
      }
    }
  }
  else {
    FUN_800200e8(0x7d,0);
    if (*(short *)(&DAT_803dc060 + (uint)*(byte *)(pfVar7 + 7) * 2) == 0x7d) {
      *(byte *)(pfVar7 + 7) = *(byte *)(pfVar7 + 7) + 1;
    }
    else {
      *(undefined *)(pfVar7 + 7) = 0;
    }
  }
  if (2 < *(byte *)(pfVar7 + 7)) {
    FUN_800200e8(0x80,1);
    *(undefined *)(pfVar7 + 7) = 0;
  }
  if ((*(byte *)((int)pfVar7 + 0x1f) & 1) != 0) {
    *(byte *)((int)pfVar7 + 0x1f) = *(byte *)((int)pfVar7 + 0x1f) & 0xfe;
    FUN_800200e8(0x60f,1);
    iVar2 = FUN_8001ffb4(0x7a);
    if (iVar2 == 0) {
      iVar2 = FUN_8001ffb4(0x627);
      if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0x63e), iVar2 != 0)) {
        FUN_800200e8(0x61c,1);
      }
    }
    else {
      iVar2 = FUN_8001ffb4(0x61c);
      if (iVar2 != 0) {
        FUN_800200e8(0x85,1);
      }
    }
  }
  if (*(char *)((int)pfVar7 + 0x1d) == '\0') {
    iVar2 = FUN_8001ffb4(0x60e);
    if (iVar2 != 0) {
      FUN_800200e8(0x60e,0);
      FUN_8012df14();
    }
  }
  else if ((*(char *)((int)pfVar7 + 0x1d) == '\x05') && (iVar2 = FUN_8001ffb4(0x60e), iVar2 != 0)) {
    FUN_800200e8(0x60e,0);
    FUN_8001467c();
    iVar2 = FUN_8001ffb4(0x7a);
    if (iVar2 != 0) {
      FUN_800200e8(0x85,1);
    }
    pfVar7[4] = FLOAT_803e5550;
    (**(code **)(*DAT_803dca4c + 8))(0x73,1);
    *(undefined *)((int)pfVar7 + 0x1d) = 0;
    FUN_8000bb18(0,0x10a);
  }
  iVar2 = FUN_8001ffb4(0x647);
  if (iVar2 != 0) {
    FUN_800200e8(0x612,1);
    FUN_800200e8(0x90b,1);
    FUN_800200e8(0x87,1);
  }
  iVar2 = FUN_8001ffb4(0xbde);
  if (iVar2 != 0) {
    FUN_800200e8(0x2c6,1);
    FUN_800200e8(0x2ce,1);
    FUN_800200e8(0xbdc,1);
  }
  iVar2 = FUN_8001ffb4(0xbe5);
  if (iVar2 != 0) {
    FUN_800200e8(0xbdf,1);
    FUN_800200e8(0xbe1,1);
    FUN_800200e8(0xbe3,1);
  }
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8002b9ec();
  if (*(char *)(iVar2 + 0x1d) == '\x05') {
    FUN_800200e8(0x60f,1);
    iVar3 = FUN_80014670();
    if (iVar3 != 0) {
      iVar3 = FUN_8001ffb4(0x7a);
      if (iVar3 != 0) {
        FUN_800200e8(0x85,1);
      }
      *(float *)(iVar2 + 0x10) = FLOAT_803e5550;
      *(undefined *)(iVar2 + 0x1d) = 0;
      FUN_8000bb18(0,0x10a);
      FUN_8000a518(0xef,0);
    }
  }
  iVar2 = FUN_8001ffb4(0x4d0);
  if ((iVar2 == 0) && (iVar2 = FUN_8001ffb4(0x2b5), iVar2 != 0)) {
    FUN_800200e8(0x4d0,1);
    (**(code **)(*DAT_803dcaac + 0x50))(0xe,2,1);
    FUN_800552e8(0x50,0);
    (**(code **)(*DAT_803dcaac + 0x50))(0xe,1,0);
  }
  iVar2 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar2 == 0) {
    if (*(char *)(pfVar7 + 8) != '3') {
      *(undefined *)(pfVar7 + 8) = 0x33;
      FUN_8000a518(0x33,1);
    }
    if (*(char *)((int)pfVar7 + 0x21) != '\"') {
      *(undefined *)((int)pfVar7 + 0x21) = 0x22;
      FUN_8000a518(0x22,1);
    }
  }
  else {
    if (*(char *)(pfVar7 + 8) != '-') {
      *(undefined *)(pfVar7 + 8) = 0x2d;
      FUN_8000a518(0x2d,1);
    }
    if (*(char *)((int)pfVar7 + 0x21) != -1) {
      *(undefined *)((int)pfVar7 + 0x21) = 0xff;
      FUN_8000a518(0x22,0);
    }
  }
  FUN_801d7ed4(pfVar7 + 6,1,0xffffffff,0xffffffff,0xe1e,0x36);
  FUN_801d7ed4(pfVar7 + 6,2,0xffffffff,0xffffffff,0xcbb,0xc4);
  if ((*(byte *)((int)pfVar7 + 0x1f) & 2) != 0) {
    FUN_800200e8(0x60e,1);
    *(byte *)((int)pfVar7 + 0x1f) = *(byte *)((int)pfVar7 + 0x1f) & 0xfd;
  }
  return;
}

