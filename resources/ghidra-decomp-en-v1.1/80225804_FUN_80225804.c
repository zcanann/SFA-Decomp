// Function: FUN_80225804
// Entry: 80225804
// Size: 1496 bytes

void FUN_80225804(undefined4 param_1,int param_2)

{
  float fVar1;
  byte bVar4;
  uint uVar2;
  short *psVar3;
  undefined auStack_18 [20];
  
  (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_18);
  bVar4 = *(byte *)(param_2 + 0x10);
  if (bVar4 != 5) {
    if (bVar4 < 5) {
      if (3 < bVar4) {
        uVar2 = FUN_80020078(0x2a5);
        if (uVar2 == 0) {
          bVar4 = FUN_8001469c();
          if (bVar4 != 0) {
            FUN_800201ac(0x274,0);
            FUN_800201ac(0xef1,0);
            uVar2 = FUN_80020078(0x34d);
            if (uVar2 == 0) {
              FUN_800201ac(0x2b1,0);
              FUN_800201ac(0x226,1);
              FUN_800201ac(0x2a6,1);
              FUN_800201ac(0x206,1);
              FUN_800201ac(0x25f,1);
              *(undefined *)(param_2 + 0x10) = 0;
            }
          }
        }
        else {
          FUN_800201ac(0x274,1);
          FUN_800201ac(0xef1,0);
          psVar3 = (short *)FUN_8002bac4();
          (**(code **)(*DAT_803dd72c + 0x1c))(psVar3 + 6,(int)*psVar3,1,0);
          *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 0x40;
          *(undefined *)(param_2 + 0x10) = 0;
          FUN_8000bb38(0,0x7e);
          FUN_800146a8();
        }
        goto LAB_802259f8;
      }
    }
    else if (bVar4 < 7) {
      FUN_800146e8(0x1d,0x50);
      FUN_800146c8();
      *(undefined *)(param_2 + 0x10) = 4;
      goto LAB_802259f8;
    }
  }
  if (((*(ushort *)(param_2 + 0x1e) & 0x40) == 0) && (uVar2 = FUN_80020078(0x2b1), uVar2 != 0)) {
    FUN_800201ac(0xef1,1);
    FUN_800201ac(0xe6d,0);
    uVar2 = FUN_80020078(0x204);
    if (uVar2 != 0) {
      FUN_800201ac(0x226,0);
      FUN_800201ac(0x2a6,0);
      FUN_800201ac(0x206,0);
      FUN_800201ac(0x25f,0);
      FUN_800201ac(0x274,1);
      *(undefined *)(param_2 + 0x10) = 6;
    }
  }
LAB_802259f8:
  if ((*(ushort *)(param_2 + 0x1e) & 0x10) == 0) {
    uVar2 = FUN_80020078(0x810);
    if ((uVar2 & 0xff) == 4) {
      FUN_800201ac(0x812,1);
      FUN_8000bb38(0,0x7e);
      *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 0x10;
    }
    else {
      uVar2 = FUN_80020078(0x808);
      if ((uVar2 != 0) && (*(float *)(param_2 + 0xc) <= FLOAT_803e7a40)) {
        FUN_800201ac(0x810,0);
        FUN_80003494(0x803adf38,0x8032bc60,0x40);
        *(float *)(param_2 + 0xc) = FLOAT_803e7a44;
      }
    }
    fVar1 = FLOAT_803e7a40;
    if ((FLOAT_803e7a40 < *(float *)(param_2 + 0xc)) &&
       (*(float *)(param_2 + 0xc) = *(float *)(param_2 + 0xc) - FLOAT_803dc074,
       *(float *)(param_2 + 0xc) <= fVar1)) {
      FUN_800201ac(0x808,0);
    }
  }
  if ((*(ushort *)(param_2 + 0x1e) & 0x20) == 0) {
    uVar2 = FUN_80020078(0x811);
    if ((uVar2 & 0xff) == 4) {
      FUN_800201ac(0x813,1);
      FUN_8000bb38(0,0x7e);
      *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 0x20;
    }
    else {
      uVar2 = FUN_80020078(0x809);
      if ((uVar2 != 0) && (*(float *)(param_2 + 8) <= FLOAT_803e7a40)) {
        FUN_800201ac(0x811,0);
        FUN_80003494(0x803adef8,0x8032bce0,0x40);
        *(float *)(param_2 + 8) = FLOAT_803e7a44;
      }
    }
    fVar1 = FLOAT_803e7a40;
    if ((FLOAT_803e7a40 < *(float *)(param_2 + 8)) &&
       (*(float *)(param_2 + 8) = *(float *)(param_2 + 8) - FLOAT_803dc074,
       *(float *)(param_2 + 8) <= fVar1)) {
      FUN_800201ac(0x809,0);
    }
  }
  if ((*(ushort *)(param_2 + 0x1e) & 0x80) == 0) {
    uVar2 = FUN_80020078(0xc58);
    if (((uVar2 == 0) || (uVar2 = FUN_80020078(0xc59), uVar2 == 0)) ||
       (uVar2 = FUN_80020078(0xc5a), uVar2 == 0)) {
      if (((*(byte *)(param_2 + 0x18) >> 6 & 1) == 0) && (uVar2 = FUN_80020078(0xc58), uVar2 != 0))
      {
        FUN_8000bb38(0,0x109);
        *(byte *)(param_2 + 0x18) = *(byte *)(param_2 + 0x18) & 0xbf | 0x40;
      }
      else if (((*(byte *)(param_2 + 0x18) >> 5 & 1) == 0) &&
              (uVar2 = FUN_80020078(0xc59), uVar2 != 0)) {
        FUN_8000bb38(0,0x109);
        *(byte *)(param_2 + 0x18) = *(byte *)(param_2 + 0x18) & 0xdf | 0x20;
      }
      else if (((*(byte *)(param_2 + 0x18) >> 3 & 3) == 0) &&
              (uVar2 = FUN_80020078(0xc5a), uVar2 != 0)) {
        FUN_8000bb38(0,0x109);
        *(byte *)(param_2 + 0x18) = *(byte *)(param_2 + 0x18) & 0xe7 | 8;
      }
    }
    else {
      FUN_800201ac(0x205,1);
      FUN_8000bb38(0,0x7e);
      *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 0x80;
    }
  }
  if (((*(ushort *)(param_2 + 0x1e) & 0x100) == 0) && (uVar2 = FUN_80020078(0xbcf), uVar2 != 0)) {
    FUN_800201ac(0xbc8,0);
    FUN_800201ac(0x2f0,1);
    FUN_800201ac(0xeec,0);
    FUN_800201ac(0xbd0,0);
    psVar3 = (short *)FUN_8002bac4();
    (**(code **)(*DAT_803dd72c + 0x1c))(psVar3 + 6,(int)*psVar3,1,0);
    FUN_8000bb38(0,0x7e);
    *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) | 0x100;
  }
  *(ushort *)(param_2 + 0x1e) = *(ushort *)(param_2 + 0x1e) & 0xfffe;
  uVar2 = FUN_80020078(0xc92);
  if (uVar2 != 0) {
    FUN_800201ac(0x4e4,0);
    FUN_800201ac(0x4e5,0);
    uVar2 = FUN_80020078(0x4e3);
    if (uVar2 == 0xff) {
      uVar2 = FUN_80022264(6,7);
      FUN_800201ac(0x4e3,uVar2);
    }
  }
  return;
}

