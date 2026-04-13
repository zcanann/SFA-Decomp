// Function: FUN_802276fc
// Entry: 802276fc
// Size: 620 bytes

void FUN_802276fc(int param_1)

{
  ushort uVar1;
  uint uVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_80226228;
  FUN_800201ac(0x810,0);
  FUN_80003494(0x803adf38,0x8032bc60,0x40);
  FUN_800201ac(0x811,0);
  FUN_80003494(0x803adef8,0x8032bce0,0x40);
  *pfVar3 = FLOAT_803e7a74;
  uVar2 = FUN_80020078(0x7fa);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 8;
  }
  uVar2 = FUN_80020078(0x7f9);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 4;
  }
  uVar2 = FUN_80020078(0x813);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 0x20;
  }
  uVar2 = FUN_80020078(0x812);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 0x10;
  }
  uVar2 = FUN_80020078(0x2a5);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 0x40;
  }
  uVar2 = FUN_80020078(0x205);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 0x80;
  }
  uVar2 = FUN_80020078(0xbcf);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 0x100;
  }
  uVar2 = FUN_80020078(0xcac);
  if (uVar2 != 0) {
    *(ushort *)((int)pfVar3 + 0x1e) = *(ushort *)((int)pfVar3 + 0x1e) | 0x200;
  }
  uVar1 = *(ushort *)((int)pfVar3 + 0x1e);
  if ((uVar1 & 0x200) == 0) {
    if (((uVar1 & 4) != 0) && ((uVar1 & 8) != 0)) {
      *(undefined *)(pfVar3 + 4) = 3;
    }
  }
  else {
    *(undefined *)(pfVar3 + 4) = 7;
  }
  FUN_800372f8(param_1,9);
  FUN_800201ac(0x226,1);
  FUN_800201ac(0x2a6,1);
  FUN_800201ac(0x206,1);
  FUN_800201ac(0x25f,1);
  (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  uVar2 = FUN_80020078(0xc58);
  *(byte *)(pfVar3 + 6) = (byte)((uVar2 & 0xff) << 6) & 0x40 | *(byte *)(pfVar3 + 6) & 0xbf;
  uVar2 = FUN_80020078(0xc59);
  *(byte *)(pfVar3 + 6) = (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)(pfVar3 + 6) & 0xdf;
  uVar2 = FUN_80020078(0xc5a);
  *(byte *)(pfVar3 + 6) = (byte)((uVar2 & 0xff) << 3) & 0x18 | *(byte *)(pfVar3 + 6) & 0xe7;
  return;
}

