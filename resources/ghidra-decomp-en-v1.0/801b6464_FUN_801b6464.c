// Function: FUN_801b6464
// Entry: 801b6464
// Size: 1352 bytes

void FUN_801b6464(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  byte bVar8;
  byte bVar9;
  undefined4 uVar7;
  char cVar10;
  float *pfVar11;
  
  iVar1 = FUN_802860d8();
  uVar2 = FUN_8001ffb4(0xd0b);
  uVar3 = FUN_8001ffb4(0xd0c);
  uVar4 = FUN_8001ffb4(0xd0d);
  uVar5 = FUN_8001ffb4(0xd0e);
  pfVar11 = *(float **)(iVar1 + 0xb8);
  if ((((((uVar2 & 0xff) != 0) && (-1 < *(char *)((int)pfVar11 + 0xe))) ||
       (((uVar3 & 0xff) != 0 && ((*(byte *)((int)pfVar11 + 0xe) >> 6 & 1) == 0)))) ||
      (((uVar4 & 0xff) != 0 && ((*(byte *)((int)pfVar11 + 0xe) >> 5 & 1) == 0)))) ||
     (((uVar5 & 0xff) != 0 && ((*(byte *)((int)pfVar11 + 0xe) >> 4 & 1) == 0)))) {
    FUN_8000bb18(0,0x109);
  }
  *(byte *)((int)pfVar11 + 0xe) = (byte)((uVar2 & 0xff) << 7) | *(byte *)((int)pfVar11 + 0xe) & 0x7f
  ;
  *(byte *)((int)pfVar11 + 0xe) =
       (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)((int)pfVar11 + 0xe) & 0xbf;
  *(byte *)((int)pfVar11 + 0xe) =
       (byte)((uVar4 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar11 + 0xe) & 0xdf;
  *(byte *)((int)pfVar11 + 0xe) =
       (byte)((uVar5 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar11 + 0xe) & 0xef;
  if (((*(byte *)((int)pfVar11 + 0xe) >> 3 & 1) == 0) && (iVar6 = FUN_8001ffb4(0xa21), iVar6 != 0))
  {
    FUN_8000bb18(0,0x109);
    *(byte *)((int)pfVar11 + 0xe) = *(byte *)((int)pfVar11 + 0xe) & 0xf7 | 8;
  }
  if (*(int *)(iVar1 + 0xf4) != 0) {
    iVar6 = FUN_8001ffb4(0xa82);
    if ((iVar6 == 0) ||
       ((iVar6 = FUN_8001ffb4(0x17), iVar6 != 0 && (iVar6 = FUN_8001ffb4(0xead), iVar6 == 0)))) {
      if (*(int *)(iVar1 + 0xf4) == 2) {
        FUN_80008b74(0,0,0x160,0);
        FUN_80008b74(0,0,0x15a,0);
        FUN_80008b74(0,0,0x15c,0);
        FUN_80008b74(0,0,0x15f,0);
      }
      else {
        FUN_80008cbc(0,0,0x160,0);
        FUN_80008cbc(0,0,0x15a,0);
        FUN_80008cbc(0,0,0x15c,0);
        FUN_80008cbc(0,0,0x15f,0);
      }
    }
    *(undefined4 *)(iVar1 + 0xf4) = 0;
  }
  if (*(char *)((int)pfVar11 + 0xd) == '\0') {
    iVar1 = FUN_8001ffb4(0x651);
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dcaac + 0x50))(0x13,0xd,1);
      *(undefined *)((int)pfVar11 + 0xd) = 1;
    }
  }
  else {
    iVar1 = FUN_8001ffb4(0x651);
    if (iVar1 == 0) {
      (**(code **)(*DAT_803dcaac + 0x50))(0x13,0xd,0);
      *(undefined *)((int)pfVar11 + 0xd) = 0;
    }
  }
  if (FLOAT_803e4a24 < *pfVar11) {
    FUN_80019908(0xff,0xff,0xff,0xff);
    FUN_80016870(0x430);
    *pfVar11 = *pfVar11 - FLOAT_803db414;
    if (*pfVar11 < FLOAT_803e4a24) {
      *pfVar11 = FLOAT_803e4a24;
    }
  }
  if (*(char *)(pfVar11 + 3) == '\0') {
    bVar8 = FUN_8001ffb4(0x3e2);
    bVar9 = FUN_8001ffb4(0x3e3);
    *(byte *)(pfVar11 + 3) = bVar9 & bVar8;
    if (*(char *)(pfVar11 + 3) != '\0') {
      (**(code **)(*DAT_803dca68 + 0x38))(0x4ba,0x14,0x8c,1);
    }
  }
  uVar3 = FUN_8001ffb4(0x3e2);
  uVar7 = FUN_8001ffb4(0x3e3);
  uVar2 = countLeadingZeros(uVar7);
  uVar2 = uVar2 >> 5 & uVar3 & 0xff;
  if (uVar2 != *(byte *)(pfVar11 + 2)) {
    FUN_800200e8(1000,uVar2);
    *(char *)(pfVar11 + 2) = (char)uVar2;
  }
  cVar10 = FUN_8001ffb4(0x8a5);
  if ((cVar10 == '\0') && (iVar1 = FUN_8001ffb4(0x89d), iVar1 != 0)) {
    FUN_800200e8(0x8a4,1);
  }
  iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar1 == 0) {
    if ((*(short *)((int)pfVar11 + 10) != 0xe2) &&
       (*(undefined2 *)((int)pfVar11 + 10) = 0xe2, ((uint)pfVar11[1] & 4) != 0)) {
      FUN_8000a518(0xc5,0);
      FUN_8000a518(0xe2,1);
    }
  }
  else if ((*(short *)((int)pfVar11 + 10) != 0xc5) &&
          (*(undefined2 *)((int)pfVar11 + 10) = 0xc5, ((uint)pfVar11[1] & 4) != 0)) {
    FUN_8000a518(0xe2,0);
    FUN_8000a518(0xc5,1);
  }
  FUN_801d7ed4(pfVar11 + 1,1,0x1a7,0x64b,0xc1e,0xa1);
  FUN_801d7ed4(pfVar11 + 1,2,0x1a8,0xc0,0xc1f,0xcf);
  FUN_801d7ed4(pfVar11 + 1,4,0x1ba,0x1b9,0xc20,(int)*(short *)((int)pfVar11 + 10));
  FUN_801d7ed4(pfVar11 + 1,8,0xffffffff,0xffffffff,0xd8f,0xdc);
  FUN_801d7ed4(pfVar11 + 1,0x10,0x1a7,0x64b,0xc1e,0xed);
  FUN_801d7ed4(pfVar11 + 1,0x20,0x1a8,0xc0,0xc1f,0x36);
  FUN_801d7ed4(pfVar11 + 1,0x40,0x1ba,0x1b9,0xc20,0x35);
  FUN_801d7ed4(pfVar11 + 1,0x100,0xffffffff,0xffffffff,0x3e2,0x2b);
  FUN_80286124();
  return;
}

