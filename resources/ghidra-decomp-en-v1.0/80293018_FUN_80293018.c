// Function: FUN_80293018
// Entry: 80293018
// Size: 276 bytes

void FUN_80293018(undefined4 param_1,undefined4 param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  undefined8 uVar6;
  undefined2 local_34 [4];
  
  uVar6 = FUN_80286048();
  uVar3 = (uint)((ulonglong)uVar6 >> 0x20);
  pfVar4 = (float *)uVar6;
  local_34[0] = (undefined2)(uVar3 << 2);
  dVar5 = (double)FUN_80291e08(local_34);
  fVar1 = (float)(dVar5 * dVar5);
  fVar2 = (float)(dVar5 * (double)(fVar1 * (fVar1 * (FLOAT_803e7c5c * fVar1 + FLOAT_803e7c58) +
                                           FLOAT_803e7c54) + FLOAT_803e7c50));
  fVar1 = fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7c6c * fVar1 + FLOAT_803e7c68) + FLOAT_803e7c64) +
                  FLOAT_803e7c60) + FLOAT_803e7c40;
  uVar3 = (uVar3 & 0xffff) + 0x2000 & 0xc000;
  if (uVar3 == 0x4000) {
    *pfVar4 = fVar1;
    *param_3 = -fVar2;
  }
  else {
    if (uVar3 < 0x4000) {
      if (uVar3 == 0) {
        *pfVar4 = fVar2;
        *param_3 = fVar1;
        goto LAB_80293110;
      }
    }
    else if (uVar3 == 0x8000) {
      *pfVar4 = -fVar2;
      *param_3 = -fVar1;
      goto LAB_80293110;
    }
    *pfVar4 = -fVar1;
    *param_3 = fVar2;
  }
LAB_80293110:
  FUN_80286094();
  return;
}

