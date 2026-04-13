// Function: FUN_80293778
// Entry: 80293778
// Size: 276 bytes

void FUN_80293778(undefined4 param_1,undefined4 param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  undefined8 uVar6;
  undefined2 local_34 [4];
  
  uVar6 = FUN_802867ac();
  uVar3 = (uint)((ulonglong)uVar6 >> 0x20);
  pfVar4 = (float *)uVar6;
  local_34[0] = (undefined2)(uVar3 << 2);
  dVar5 = FUN_80292568((float *)local_34);
  fVar1 = (float)(dVar5 * dVar5);
  fVar2 = (float)(dVar5 * (double)(fVar1 * (fVar1 * (FLOAT_803e88f4 * fVar1 + FLOAT_803e88f0) +
                                           FLOAT_803e88ec) + FLOAT_803e88e8));
  fVar1 = fVar1 * (fVar1 * (fVar1 * (FLOAT_803e8904 * fVar1 + FLOAT_803e8900) + FLOAT_803e88fc) +
                  FLOAT_803e88f8) + FLOAT_803e88d8;
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
        goto LAB_80293870;
      }
    }
    else if (uVar3 == 0x8000) {
      *pfVar4 = -fVar2;
      *param_3 = -fVar1;
      goto LAB_80293870;
    }
    *pfVar4 = -fVar1;
    *param_3 = fVar2;
  }
LAB_80293870:
  FUN_802867f8();
  return;
}

