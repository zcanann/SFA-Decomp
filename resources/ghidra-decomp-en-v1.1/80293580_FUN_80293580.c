// Function: FUN_80293580
// Entry: 80293580
// Size: 244 bytes

void FUN_80293580(undefined4 param_1,undefined4 param_2,float *param_3)

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
  fVar2 = (float)(dVar5 * (double)(FLOAT_803e88bc * fVar1 + FLOAT_803e88b8));
  fVar1 = fVar1 * (FLOAT_803e88c8 * fVar1 + FLOAT_803e88c4) + FLOAT_803e88c0;
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
        goto LAB_80293658;
      }
    }
    else if (uVar3 == 0x8000) {
      *pfVar4 = -fVar2;
      *param_3 = -fVar1;
      goto LAB_80293658;
    }
    *pfVar4 = -fVar1;
    *param_3 = fVar2;
  }
LAB_80293658:
  FUN_802867f8();
  return;
}

