// Function: FUN_8002208c
// Entry: 8002208c
// Size: 276 bytes

uint FUN_8002208c(double param_1,double param_2,float *param_3)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  double local_28;
  
  fVar1 = FLOAT_803de7f4;
  *param_3 = *param_3 + FLOAT_803db414 / FLOAT_803de7f4;
  if ((double)*param_3 <= param_1) {
    uVar3 = 0;
  }
  else {
    if ((double)*param_3 <= param_2) {
      uVar3 = (uint)(FLOAT_803db418 * fVar1 * (float)(param_2 - param_1));
      if (uVar3 == 0) {
        iVar2 = 0;
      }
      else {
        uVar4 = FUN_80292dc0();
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        iVar2 = (int)(((float)(local_28 - DOUBLE_803de800) / FLOAT_803de7f8) *
                      ((FLOAT_803de7c4 +
                       (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803de7e0)) -
                      FLOAT_803de7c0) + FLOAT_803de7c0);
      }
      uVar3 = countLeadingZeros(iVar2);
      uVar3 = uVar3 >> 5;
    }
    else {
      uVar3 = 1;
    }
    if (uVar3 != 0) {
      *param_3 = FLOAT_803de7c0;
    }
  }
  return uVar3;
}

