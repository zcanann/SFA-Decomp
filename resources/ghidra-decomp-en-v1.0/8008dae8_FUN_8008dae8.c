// Function: FUN_8008dae8
// Entry: 8008dae8
// Size: 252 bytes

void FUN_8008dae8(undefined4 param_1)

{
  float fVar1;
  uint uVar2;
  
  if (DAT_803dd184 == 0) {
    FUN_8002ad30(param_1,0,0,0,0,0);
  }
  if ((DAT_803db750 == '\0') && ((*(ushort *)(DAT_803dd184 + 4) & 1) == 0)) {
    fVar1 = *(float *)(DAT_803dd184 + 0x14);
    if (FLOAT_803df108 <= fVar1) {
      if (fVar1 <= FLOAT_803df148) {
        uVar2 = (uint)-(FLOAT_803df118 * (fVar1 / FLOAT_803df148) - FLOAT_803df118);
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0xff;
    }
    FUN_8002ad30(param_1,*(uint *)(DAT_803dd184 + 0x24) & 0xff,*(uint *)(DAT_803dd184 + 0x28) & 0xff
                 ,*(uint *)(DAT_803dd184 + 0x2c) & 0xff,uVar2 & 0xff,1);
  }
  else {
    FUN_8002ad30(param_1,0,0,0,0,0);
  }
  return;
}

