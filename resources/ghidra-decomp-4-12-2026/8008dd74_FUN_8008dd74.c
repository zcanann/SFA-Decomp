// Function: FUN_8008dd74
// Entry: 8008dd74
// Size: 252 bytes

void FUN_8008dd74(undefined4 param_1)

{
  float fVar1;
  uint uVar2;
  
  if (DAT_803dde04 == 0) {
    FUN_8002ae08(param_1,0,0,0,0,0);
  }
  if ((DAT_803dc3b0 == '\0') && ((*(ushort *)(DAT_803dde04 + 4) & 1) == 0)) {
    fVar1 = *(float *)(DAT_803dde04 + 0x14);
    if (FLOAT_803dfd88 <= fVar1) {
      if (fVar1 <= FLOAT_803dfdc8) {
        uVar2 = (uint)-(FLOAT_803dfd98 * (fVar1 / FLOAT_803dfdc8) - FLOAT_803dfd98);
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0xff;
    }
    FUN_8002ae08(param_1,*(uint *)(DAT_803dde04 + 0x24) & 0xff,*(uint *)(DAT_803dde04 + 0x28) & 0xff
                 ,*(uint *)(DAT_803dde04 + 0x2c) & 0xff,uVar2 & 0xff,1);
  }
  else {
    FUN_8002ae08(param_1,0,0,0,0,0);
  }
  return;
}

