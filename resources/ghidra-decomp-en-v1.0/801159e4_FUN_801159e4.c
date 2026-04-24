// Function: FUN_801159e4
// Entry: 801159e4
// Size: 880 bytes

void FUN_801159e4(void)

{
  undefined4 uVar1;
  byte bVar3;
  int iVar2;
  uint local_18;
  uint local_14;
  double local_10;
  double local_8;
  
  if (DAT_803dd5ec < 0xf0) {
    if (DAT_803dd5ec < 0x1e) {
      local_10 = (double)CONCAT44(0x43300000,DAT_803dd5ec);
      iVar2 = (int)((FLOAT_803e1cf4 * (float)(local_10 - DOUBLE_803e1ce8)) / FLOAT_803e1cf8);
      local_8 = (double)(longlong)iVar2;
      bVar3 = (byte)iVar2;
    }
    else if (DAT_803dd5ec < 0xd2) {
      bVar3 = 0xff;
    }
    else {
      local_8 = (double)CONCAT44(0x43300000,0xf0 - DAT_803dd5ec);
      iVar2 = (int)((FLOAT_803e1cf4 * (float)(local_8 - DOUBLE_803e1ce8)) / FLOAT_803e1cf8);
      local_10 = (double)(longlong)iVar2;
      bVar3 = (byte)iVar2;
    }
    if (DAT_803dc968 == '\0') {
      local_18 = 0xdc000000;
    }
    else {
      local_18 = 0x46ff00;
    }
    local_18 = local_18 | bVar3;
    local_14 = local_18;
    FUN_80076d78(DAT_803a4438,0x85,0xaa,&local_14,0x100,0);
  }
  else if (DAT_803dd5ec < 0x1e0) {
    if (DAT_803dd5ec < 0x10e) {
      local_8 = (double)CONCAT44(0x43300000,DAT_803dd5ec - 0xf0);
      iVar2 = (int)((FLOAT_803e1cf4 * (float)(local_8 - DOUBLE_803e1ce8)) / FLOAT_803e1cf8);
    }
    else if (DAT_803dd5ec < 0x1c2) {
      iVar2 = 0xff;
    }
    else {
      local_8 = (double)CONCAT44(0x43300000,0x1e0 - DAT_803dd5ec);
      iVar2 = (int)((FLOAT_803e1cf4 * (float)(local_8 - DOUBLE_803e1ce8)) / FLOAT_803e1cf8);
    }
    local_8 = (double)CONCAT44(0x43300000,(int)(0x280 - (uint)*(ushort *)(DAT_803a443c + 10)) >> 1);
    local_10 = (double)CONCAT44(0x43300000,(int)(0x1e0 - (uint)*(ushort *)(DAT_803a443c + 0xc)) >> 1
                               );
    FUN_8007719c((double)(float)(local_8 - DOUBLE_803e1ce8),
                 (double)(float)(local_10 - DOUBLE_803e1ce8),DAT_803a443c,iVar2,0x119);
  }
  else if (DAT_803dd5ec < 600) {
    if (DAT_803dd5ec < 0x1fe) {
      local_8 = (double)CONCAT44(0x43300000,DAT_803dd5ec - 0x1e0);
      iVar2 = (int)((FLOAT_803e1cf4 * (float)(local_8 - DOUBLE_803e1ce8)) / FLOAT_803e1cf8);
    }
    else if (DAT_803dd5ec < 0x23a) {
      iVar2 = 0xff;
    }
    else {
      local_8 = (double)CONCAT44(0x43300000,600 - DAT_803dd5ec);
      iVar2 = (int)((FLOAT_803e1cf4 * (float)(local_8 - DOUBLE_803e1ce8)) / FLOAT_803e1cf8);
    }
    local_8 = (double)CONCAT44(0x43300000,(int)(0x280 - (uint)*(ushort *)(DAT_803a4440 + 10)) >> 1);
    local_10 = (double)CONCAT44(0x43300000,(int)(0x1e0 - (uint)*(ushort *)(DAT_803a4440 + 0xc)) >> 1
                               );
    FUN_8007719c((double)(float)(local_8 - DOUBLE_803e1ce8),
                 (double)(float)(local_10 - DOUBLE_803e1ce8),DAT_803a4440,iVar2,0x119);
  }
  if (DAT_803dc950 == '\0') {
    DAT_803dd5ec = DAT_803dd5ec + 1;
  }
  else {
    DAT_803dd5e8 = '\x01';
  }
  if (((DAT_803dd5e8 != '\0') && (600 < DAT_803dd5ec)) && (DAT_803dc950 == '\0')) {
    FUN_80019908(0xff,0xff,0xff,0xff);
    uVar1 = FUN_80019444(0x565);
    FUN_80015dc8(uVar1,0,0x118,300);
  }
  return;
}

