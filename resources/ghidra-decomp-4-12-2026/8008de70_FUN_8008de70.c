// Function: FUN_8008de70
// Entry: 8008de70
// Size: 196 bytes

void FUN_8008de70(undefined4 param_1)

{
  float fVar1;
  undefined uStack_1;
  
  if (DAT_803dde04 != 0) {
    if ((DAT_803dc3b0 == '\0') && ((*(ushort *)(DAT_803dde04 + 4) & 1) == 0)) {
      fVar1 = *(float *)(DAT_803dde04 + 0x14);
      if (FLOAT_803dfd88 <= fVar1) {
        if (fVar1 <= FLOAT_803dfdc8) {
          uStack_1 = (undefined)(int)-(FLOAT_803dfd98 * (fVar1 / FLOAT_803dfdc8) - FLOAT_803dfd98);
        }
        else {
          uStack_1 = 0;
        }
      }
      else {
        uStack_1 = 0xff;
      }
      FUN_8005d294(param_1,(char)*(undefined4 *)(DAT_803dde04 + 0x24),
                   (char)*(undefined4 *)(DAT_803dde04 + 0x28),
                   (char)*(undefined4 *)(DAT_803dde04 + 0x2c),uStack_1);
    }
    else {
      FUN_8005d294(param_1,0xff,0xff,0xff,0);
    }
  }
  return;
}

