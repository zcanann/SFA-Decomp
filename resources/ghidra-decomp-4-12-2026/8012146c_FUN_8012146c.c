// Function: FUN_8012146c
// Entry: 8012146c
// Size: 348 bytes

void FUN_8012146c(undefined4 param_1,undefined4 *param_2)

{
  float fVar1;
  uint uVar2;
  
  if (-1 < (int)param_2[1]) {
    param_2[1] = param_2[1] - (uint)DAT_803dc070;
    fVar1 = FLOAT_803e2b40;
    if ((int)param_2[1] < 0) {
      FUN_80054484();
      *param_2 = 0;
    }
    else {
      uVar2 = param_2[1] ^ 0x80000000;
      if (FLOAT_803e2c1c <= (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e2af8)) {
        if (FLOAT_803e2b40 != (float)param_2[2]) {
          param_2[2] = FLOAT_803e2c20 *
                       (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e2b08) +
                       (float)param_2[2];
          if (fVar1 < (float)param_2[2]) {
            param_2[2] = fVar1;
          }
        }
      }
      else {
        param_2[2] = (FLOAT_803e2b40 * (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e2af8)
                     ) / FLOAT_803e2c1c;
      }
      FUN_800033a8(-0x7fc55f78,0,0xc);
      DAT_803aa088 = *param_2;
      DAT_803aa094 = 0;
      FUN_80077318((double)FLOAT_803e2c24,
                   (double)(float)((double)CONCAT44(0x43300000,DAT_803de3c0 + 0xafU ^ 0x80000000) -
                                  DOUBLE_803e2af8),-0x7fc55f78,(int)(float)param_2[2],0x100);
    }
  }
  return;
}

