// Function: FUN_8008d904
// Entry: 8008d904
// Size: 108 bytes

int FUN_8008d904(void)

{
  float fVar1;
  int iVar2;
  
  if (DAT_803dd184 == 0) {
    iVar2 = 0xff;
  }
  else {
    fVar1 = *(float *)(DAT_803dd184 + 0x14);
    if (FLOAT_803df138 <= fVar1) {
      if (fVar1 <= FLOAT_803df13c) {
        iVar2 = (int)(FLOAT_803df118 * ((fVar1 - FLOAT_803df138) / FLOAT_803df140));
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

