// Function: FUN_8008db90
// Entry: 8008db90
// Size: 108 bytes

int FUN_8008db90(void)

{
  float fVar1;
  int iVar2;
  
  if (DAT_803dde04 == 0) {
    iVar2 = 0xff;
  }
  else {
    fVar1 = *(float *)(DAT_803dde04 + 0x14);
    if (FLOAT_803dfdb8 <= fVar1) {
      if (fVar1 <= FLOAT_803dfdbc) {
        iVar2 = (int)(FLOAT_803dfd98 * ((fVar1 - FLOAT_803dfdb8) / FLOAT_803dfdc0));
      }
      else {
        iVar2 = 0xff;
      }
    }
    else {
      iVar2 = 0;
    }
  }
  return iVar2;
}

