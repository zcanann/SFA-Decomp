// Function: FUN_801b6a18
// Entry: 801b6a18
// Size: 1352 bytes

void FUN_801b6a18(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  iVar1 = FUN_8028683c();
  uVar7 = extraout_f1;
  uVar2 = FUN_80020078(0xd0b);
  uVar3 = FUN_80020078(0xd0c);
  uVar4 = FUN_80020078(0xd0d);
  uVar5 = FUN_80020078(0xd0e);
  pfVar6 = *(float **)(iVar1 + 0xb8);
  if ((((((uVar2 & 0xff) != 0) && (-1 < *(char *)((int)pfVar6 + 0xe))) ||
       (((uVar3 & 0xff) != 0 && ((*(byte *)((int)pfVar6 + 0xe) >> 6 & 1) == 0)))) ||
      (((uVar4 & 0xff) != 0 && ((*(byte *)((int)pfVar6 + 0xe) >> 5 & 1) == 0)))) ||
     (((uVar5 & 0xff) != 0 && ((*(byte *)((int)pfVar6 + 0xe) >> 4 & 1) == 0)))) {
    uVar7 = FUN_8000bb38(0,0x109);
  }
  *(byte *)((int)pfVar6 + 0xe) = (byte)((uVar2 & 0xff) << 7) | *(byte *)((int)pfVar6 + 0xe) & 0x7f;
  *(byte *)((int)pfVar6 + 0xe) =
       (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)((int)pfVar6 + 0xe) & 0xbf;
  *(byte *)((int)pfVar6 + 0xe) =
       (byte)((uVar4 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar6 + 0xe) & 0xdf;
  *(byte *)((int)pfVar6 + 0xe) =
       (byte)((uVar5 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar6 + 0xe) & 0xef;
  if (((*(byte *)((int)pfVar6 + 0xe) >> 3 & 1) == 0) && (uVar2 = FUN_80020078(0xa21), uVar2 != 0)) {
    uVar7 = FUN_8000bb38(0,0x109);
    *(byte *)((int)pfVar6 + 0xe) = *(byte *)((int)pfVar6 + 0xe) & 0xf7 | 8;
  }
  if (*(int *)(iVar1 + 0xf4) != 0) {
    uVar2 = FUN_80020078(0xa82);
    if ((uVar2 == 0) ||
       ((uVar2 = FUN_80020078(0x17), uVar2 != 0 && (uVar2 = FUN_80020078(0xead), uVar2 == 0)))) {
      if (*(int *)(iVar1 + 0xf4) == 2) {
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x160
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15a
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15c
                             ,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15f,0,in_r7
                     ,in_r8,in_r9,in_r10);
      }
      else {
        uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x160
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15a
                             ,0,in_r7,in_r8,in_r9,in_r10);
        uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15c
                             ,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x15f,0,in_r7
                     ,in_r8,in_r9,in_r10);
      }
    }
    *(undefined4 *)(iVar1 + 0xf4) = 0;
  }
  if (*(char *)((int)pfVar6 + 0xd) == '\0') {
    uVar2 = FUN_80020078(0x651);
    if (uVar2 != 0) {
      (**(code **)(*DAT_803dd72c + 0x50))(0x13,0xd,1);
      *(undefined *)((int)pfVar6 + 0xd) = 1;
    }
  }
  else {
    uVar2 = FUN_80020078(0x651);
    if (uVar2 == 0) {
      (**(code **)(*DAT_803dd72c + 0x50))(0x13,0xd,0);
      *(undefined *)((int)pfVar6 + 0xd) = 0;
    }
  }
  if (FLOAT_803e56bc < *pfVar6) {
    uVar7 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x430);
    *pfVar6 = *pfVar6 - FLOAT_803dc074;
    if (*pfVar6 < FLOAT_803e56bc) {
      *pfVar6 = FLOAT_803e56bc;
    }
  }
  if (*(char *)(pfVar6 + 3) == '\0') {
    uVar2 = FUN_80020078(0x3e2);
    uVar3 = FUN_80020078(0x3e3);
    *(byte *)(pfVar6 + 3) = (byte)uVar3 & (byte)uVar2;
    if (*(char *)(pfVar6 + 3) != '\0') {
      (**(code **)(*DAT_803dd6e8 + 0x38))(0x4ba,0x14,0x8c,1);
    }
  }
  uVar3 = FUN_80020078(0x3e2);
  uVar2 = FUN_80020078(0x3e3);
  uVar2 = countLeadingZeros(uVar2);
  uVar3 = uVar2 >> 5 & uVar3;
  uVar2 = uVar3 & 0xff;
  if (uVar2 != *(byte *)(pfVar6 + 2)) {
    FUN_800201ac(1000,uVar2);
    *(char *)(pfVar6 + 2) = (char)uVar3;
  }
  uVar2 = FUN_80020078(0x8a5);
  if (((uVar2 & 0xff) == 0) && (uVar2 = FUN_80020078(0x89d), uVar2 != 0)) {
    FUN_800201ac(0x8a4,1);
  }
  iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar1 == 0) {
    if ((*(short *)((int)pfVar6 + 10) != 0xe2) &&
       (*(undefined2 *)((int)pfVar6 + 10) = 0xe2, ((uint)pfVar6[1] & 4) != 0)) {
      FUN_8000a538((int *)0xc5,0);
      FUN_8000a538((int *)0xe2,1);
    }
  }
  else if ((*(short *)((int)pfVar6 + 10) != 0xc5) &&
          (*(undefined2 *)((int)pfVar6 + 10) = 0xc5, ((uint)pfVar6[1] & 4) != 0)) {
    FUN_8000a538((int *)0xe2,0);
    FUN_8000a538((int *)0xc5,1);
  }
  FUN_801d84c4(pfVar6 + 1,1,0x1a7,0x64b,0xc1e,(int *)0xa1);
  FUN_801d84c4(pfVar6 + 1,2,0x1a8,0xc0,0xc1f,(int *)0xcf);
  FUN_801d84c4(pfVar6 + 1,4,0x1ba,0x1b9,0xc20,(int *)(int)*(short *)((int)pfVar6 + 10));
  FUN_801d84c4(pfVar6 + 1,8,-1,-1,0xd8f,(int *)0xdc);
  FUN_801d84c4(pfVar6 + 1,0x10,0x1a7,0x64b,0xc1e,(int *)0xed);
  FUN_801d84c4(pfVar6 + 1,0x20,0x1a8,0xc0,0xc1f,(int *)0x36);
  FUN_801d84c4(pfVar6 + 1,0x40,0x1ba,0x1b9,0xc20,(int *)0x35);
  FUN_801d84c4(pfVar6 + 1,0x100,-1,-1,0x3e2,(int *)0x2b);
  FUN_80286888();
  return;
}

