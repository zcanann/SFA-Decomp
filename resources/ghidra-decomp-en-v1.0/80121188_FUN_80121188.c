// Function: FUN_80121188
// Entry: 80121188
// Size: 348 bytes

void FUN_80121188(undefined4 param_1,undefined4 *param_2)

{
  float fVar1;
  uint uVar2;
  
  if (-1 < (int)param_2[1]) {
    param_2[1] = param_2[1] - (uint)DAT_803db410;
    fVar1 = FLOAT_803e1ec0;
    if ((int)param_2[1] < 0) {
      FUN_80054308(*param_2);
      *param_2 = 0;
    }
    else {
      uVar2 = param_2[1] ^ 0x80000000;
      if (FLOAT_803e1f9c <= (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e1e78)) {
        if (FLOAT_803e1ec0 != (float)param_2[2]) {
          param_2[2] = FLOAT_803e1fa0 *
                       (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e1e88) +
                       (float)param_2[2];
          if (fVar1 < (float)param_2[2]) {
            param_2[2] = fVar1;
          }
        }
      }
      else {
        param_2[2] = (FLOAT_803e1ec0 * (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e1e78)
                     ) / FLOAT_803e1f9c;
      }
      FUN_800033a8(&DAT_803a9428,0,0xc);
      DAT_803a9428 = *param_2;
      DAT_803a9434 = 0;
      FUN_8007719c((double)FLOAT_803e1fa4,
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803dd740 + 0xafU ^ 0x80000000) -
                                  DOUBLE_803e1e78),&DAT_803a9428,(int)(float)param_2[2],0x100);
    }
  }
  return;
}

