// Function: FUN_80251290
// Entry: 80251290
// Size: 256 bytes

void FUN_80251290(void)

{
  uint uVar1;
  
  if ((DAT_803deccc == (int *)0x0) && (DAT_803decc0 != (int *)0x0)) {
    DAT_803deccc = DAT_803decc0;
    DAT_803decc0 = (int *)*DAT_803decc0;
  }
  if (DAT_803deccc != (int *)0x0) {
    uVar1 = DAT_803deccc[6];
    if (DAT_803decd8 < uVar1) {
      if (DAT_803deccc[2] == 0) {
        FUN_80250748(0,DAT_803deccc[4],DAT_803deccc[5],DAT_803decd8);
      }
      else {
        FUN_80250748(DAT_803deccc[2],DAT_803deccc[5],DAT_803deccc[4],DAT_803decd8);
      }
    }
    else {
      if (DAT_803deccc[2] == 0) {
        FUN_80250748(0,DAT_803deccc[4],DAT_803deccc[5],uVar1);
      }
      else {
        FUN_80250748(DAT_803deccc[2],DAT_803deccc[5],DAT_803deccc[4],uVar1);
      }
      DAT_803decd4 = DAT_803deccc[7];
    }
    DAT_803deccc[6] = DAT_803deccc[6] - DAT_803decd8;
    DAT_803deccc[4] = DAT_803deccc[4] + DAT_803decd8;
    DAT_803deccc[5] = DAT_803deccc[5] + DAT_803decd8;
  }
  return;
}

