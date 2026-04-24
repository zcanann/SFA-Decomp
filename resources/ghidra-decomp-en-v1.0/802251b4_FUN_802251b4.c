// Function: FUN_802251b4
// Entry: 802251b4
// Size: 1496 bytes

void FUN_802251b4(undefined4 param_1,int param_2)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  char cVar6;
  short *psVar4;
  undefined4 uVar5;
  undefined auStack24 [20];
  
  (**(code **)(*DAT_803dca58 + 0x24))(auStack24);
  bVar1 = *(byte *)(param_2 + 0xc);
  if (bVar1 != 5) {
    if (bVar1 < 5) {
      if (3 < bVar1) {
        iVar3 = FUN_8001ffb4(0x2a5);
        if (iVar3 == 0) {
          iVar3 = FUN_80014670();
          if (iVar3 != 0) {
            FUN_800200e8(0x274,0);
            FUN_800200e8(0xef1,0);
            iVar3 = FUN_8001ffb4(0x34d);
            if (iVar3 == 0) {
              FUN_800200e8(0x2b1,0);
              FUN_800200e8(0x226,1);
              FUN_800200e8(0x2a6,1);
              FUN_800200e8(0x206,1);
              FUN_800200e8(0x25f,1);
              *(undefined *)(param_2 + 0xc) = 0;
            }
          }
        }
        else {
          FUN_800200e8(0x274,1);
          FUN_800200e8(0xef1,0);
          psVar4 = (short *)FUN_8002b9ec();
          (**(code **)(*DAT_803dcaac + 0x1c))(psVar4 + 6,(int)*psVar4,1,0);
          *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) | 0x40;
          *(undefined *)(param_2 + 0xc) = 0;
          FUN_8000bb18(0,0x7e);
          FUN_8001467c();
        }
        goto LAB_802253a8;
      }
    }
    else if (bVar1 < 7) {
      FUN_800146bc(0x1d,0x50);
      FUN_8001469c();
      *(undefined *)(param_2 + 0xc) = 4;
      goto LAB_802253a8;
    }
  }
  if (((*(ushort *)(param_2 + 0x1a) & 0x40) == 0) && (iVar3 = FUN_8001ffb4(0x2b1), iVar3 != 0)) {
    FUN_800200e8(0xef1,1);
    FUN_800200e8(0xe6d,0);
    iVar3 = FUN_8001ffb4(0x204);
    if (iVar3 != 0) {
      FUN_800200e8(0x226,0);
      FUN_800200e8(0x2a6,0);
      FUN_800200e8(0x206,0);
      FUN_800200e8(0x25f,0);
      FUN_800200e8(0x274,1);
      *(undefined *)(param_2 + 0xc) = 6;
    }
  }
LAB_802253a8:
  if ((*(ushort *)(param_2 + 0x1a) & 0x10) == 0) {
    cVar6 = FUN_8001ffb4(0x810);
    if (cVar6 == '\x04') {
      FUN_800200e8(0x812,1);
      FUN_8000bb18(0,0x7e);
      *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) | 0x10;
    }
    else {
      iVar3 = FUN_8001ffb4(0x808);
      if ((iVar3 != 0) && (*(float *)(param_2 + 8) <= FLOAT_803e6da8)) {
        FUN_800200e8(0x810,0);
        FUN_80003494(&DAT_803ad2d8,&DAT_8032b008,0x40);
        *(float *)(param_2 + 8) = FLOAT_803e6dac;
      }
    }
    fVar2 = FLOAT_803e6da8;
    if ((FLOAT_803e6da8 < *(float *)(param_2 + 8)) &&
       (*(float *)(param_2 + 8) = *(float *)(param_2 + 8) - FLOAT_803db414,
       *(float *)(param_2 + 8) <= fVar2)) {
      FUN_800200e8(0x808,0);
    }
  }
  if ((*(ushort *)(param_2 + 0x1a) & 0x20) == 0) {
    cVar6 = FUN_8001ffb4(0x811);
    if (cVar6 == '\x04') {
      FUN_800200e8(0x813,1);
      FUN_8000bb18(0,0x7e);
      *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) | 0x20;
    }
    else {
      iVar3 = FUN_8001ffb4(0x809);
      if ((iVar3 != 0) && (*(float *)(param_2 + 4) <= FLOAT_803e6da8)) {
        FUN_800200e8(0x811,0);
        FUN_80003494(&DAT_803ad298,&DAT_8032b088,0x40);
        *(float *)(param_2 + 4) = FLOAT_803e6dac;
      }
    }
    fVar2 = FLOAT_803e6da8;
    if ((FLOAT_803e6da8 < *(float *)(param_2 + 4)) &&
       (*(float *)(param_2 + 4) = *(float *)(param_2 + 4) - FLOAT_803db414,
       *(float *)(param_2 + 4) <= fVar2)) {
      FUN_800200e8(0x809,0);
    }
  }
  if ((*(ushort *)(param_2 + 0x1a) & 0x80) == 0) {
    iVar3 = FUN_8001ffb4(0xc58);
    if (((iVar3 == 0) || (iVar3 = FUN_8001ffb4(0xc59), iVar3 == 0)) ||
       (iVar3 = FUN_8001ffb4(0xc5a), iVar3 == 0)) {
      if (((*(byte *)(param_2 + 0x14) >> 6 & 1) == 0) && (iVar3 = FUN_8001ffb4(0xc58), iVar3 != 0))
      {
        FUN_8000bb18(0,0x109);
        *(byte *)(param_2 + 0x14) = *(byte *)(param_2 + 0x14) & 0xbf | 0x40;
      }
      else if (((*(byte *)(param_2 + 0x14) >> 5 & 1) == 0) &&
              (iVar3 = FUN_8001ffb4(0xc59), iVar3 != 0)) {
        FUN_8000bb18(0,0x109);
        *(byte *)(param_2 + 0x14) = *(byte *)(param_2 + 0x14) & 0xdf | 0x20;
      }
      else if (((*(byte *)(param_2 + 0x14) >> 3 & 3) == 0) &&
              (iVar3 = FUN_8001ffb4(0xc5a), iVar3 != 0)) {
        FUN_8000bb18(0,0x109);
        *(byte *)(param_2 + 0x14) = *(byte *)(param_2 + 0x14) & 0xe7 | 8;
      }
    }
    else {
      FUN_800200e8(0x205,1);
      FUN_8000bb18(0,0x7e);
      *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) | 0x80;
    }
  }
  if (((*(ushort *)(param_2 + 0x1a) & 0x100) == 0) && (iVar3 = FUN_8001ffb4(0xbcf), iVar3 != 0)) {
    FUN_800200e8(0xbc8,0);
    FUN_800200e8(0x2f0,1);
    FUN_800200e8(0xeec,0);
    FUN_800200e8(0xbd0,0);
    psVar4 = (short *)FUN_8002b9ec();
    (**(code **)(*DAT_803dcaac + 0x1c))(psVar4 + 6,(int)*psVar4,1,0);
    FUN_8000bb18(0,0x7e);
    *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) | 0x100;
  }
  *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) & 0xfffe;
  iVar3 = FUN_8001ffb4(0xc92);
  if (iVar3 != 0) {
    FUN_800200e8(0x4e4,0);
    FUN_800200e8(0x4e5,0);
    iVar3 = FUN_8001ffb4(0x4e3);
    if (iVar3 == 0xff) {
      uVar5 = FUN_800221a0(6,7);
      FUN_800200e8(0x4e3,uVar5);
    }
  }
  return;
}

