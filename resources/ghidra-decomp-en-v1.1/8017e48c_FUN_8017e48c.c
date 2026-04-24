// Function: FUN_8017e48c
// Entry: 8017e48c
// Size: 620 bytes

/* WARNING: Removing unreachable block (ram,0x8017e6d8) */
/* WARNING: Removing unreachable block (ram,0x8017e6d0) */
/* WARNING: Removing unreachable block (ram,0x8017e4a4) */
/* WARNING: Removing unreachable block (ram,0x8017e49c) */

undefined4 FUN_8017e48c(double param_1,undefined2 *param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  if (FLOAT_803e446c == *(float *)(param_3 + 0x3c)) {
    if (FLOAT_803e446c <
        *(float *)(param_3 + 0x30) - (float)((double)*(float *)(param_3 + 0x2c) - param_1)) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar6 = (double)*(float *)(param_3 + 0x40);
      dVar7 = (double)*(float *)(param_3 + 0x44);
      dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                          (double)((float)((double)FLOAT_803e4470 * dVar6) *
                                                  *(float *)(param_3 + 0x30))));
      fVar1 = (float)((double)FLOAT_803e4474 * dVar6);
      fVar2 = fVar1;
      if (fVar1 < FLOAT_803e446c) {
        fVar2 = -fVar1;
      }
      fVar3 = FLOAT_803e4460;
      if (FLOAT_803e4478 < fVar2) {
        fVar2 = (float)(-dVar7 - dVar5) / fVar1;
        fVar3 = (float)(-dVar7 + dVar5) / fVar1;
        if (FLOAT_803e446c < fVar2) {
          fVar3 = fVar2;
        }
      }
      *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
      *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
      *(float *)(param_3 + 0x30) = FLOAT_803e446c;
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
      *param_2 = *(undefined2 *)(param_3 + 0x48);
      param_2[1] = *(undefined2 *)(param_3 + 0x4a);
      param_2[2] = *(undefined2 *)(param_3 + 0x4c);
      *(float *)(param_3 + 0x44) =
           FLOAT_803e4474 * *(float *)(param_3 + 0x40) * fVar3 + *(float *)(param_3 + 0x44);
      *(undefined4 *)(param_3 + 0x3c) = *(undefined4 *)(param_3 + 0x28);
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(param_2 + 6),(double)*(float *)(param_3 + 0x34),
                 (double)*(float *)(param_2 + 10),param_2);
      uVar4 = 0;
    }
  }
  else if ((float)(param_1 - (double)*(float *)(param_3 + 0x2c)) < FLOAT_803e446c) {
    *(float *)(param_2 + 8) = (float)param_1;
    uVar4 = 1;
  }
  else {
    dVar7 = (double)(*(float *)(param_3 + 0x40) + *(float *)(param_3 + 0x3c));
    dVar6 = (double)*(float *)(param_3 + 0x44);
    dVar5 = FUN_80293900((double)(float)(dVar6 * dVar6 -
                                        (double)((float)((double)FLOAT_803e4470 * dVar7) *
                                                *(float *)(param_3 + 0x30))));
    fVar1 = (float)((double)FLOAT_803e4474 * dVar7);
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e446c) {
      fVar2 = -fVar1;
    }
    fVar3 = FLOAT_803e4460;
    if (FLOAT_803e4478 < fVar2) {
      fVar2 = (float)(-dVar6 - dVar5) / fVar1;
      fVar3 = (float)(-dVar6 + dVar5) / fVar1;
      if (FLOAT_803e446c < fVar2) {
        fVar3 = fVar2;
      }
    }
    *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
    *(float *)(param_3 + 0x3c) = FLOAT_803e4494;
    *(float *)(param_3 + 0x44) = FLOAT_803e4498;
    uVar4 = 0;
  }
  return uVar4;
}

