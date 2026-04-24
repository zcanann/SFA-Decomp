// Function: FUN_8017e22c
// Entry: 8017e22c
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x8017e46c) */
/* WARNING: Removing unreachable block (ram,0x8017e464) */
/* WARNING: Removing unreachable block (ram,0x8017e244) */
/* WARNING: Removing unreachable block (ram,0x8017e23c) */

undefined4 FUN_8017e22c(double param_1,undefined2 *param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  fVar1 = FLOAT_803e446c;
  dVar5 = (double)FLOAT_803e446c;
  dVar6 = (double)*(float *)(param_3 + 0x40);
  if (dVar5 == dVar6) {
    uVar4 = 1;
  }
  else {
    fVar2 = *(float *)(param_3 + 0x30);
    if (dVar5 <= (double)(fVar2 - (float)((double)*(float *)(param_3 + 0x2c) - param_1))) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar7 = (double)*(float *)(param_3 + 0x44);
      if (dVar5 == dVar7) {
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)FLOAT_803e4470 * dVar6) * fVar2
                                                    )));
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
        *(float *)(param_3 + 0x44) = -*(float *)(param_3 + 0x28);
        if ((*(byte *)(param_3 + 0x5a) & 8) == 0) {
          FUN_8000bb38((uint)param_2,0x407);
          *(byte *)(param_3 + 0x5a) = *(byte *)(param_3 + 0x5a) | 8;
        }
        uVar4 = 1;
      }
      else if ((double)FLOAT_803e448c <= dVar7) {
        dVar6 = (double)(float)(dVar6 + (double)*(float *)(param_3 + 0x3c));
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)FLOAT_803e4470 * dVar6) * fVar2
                                                    )));
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
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x44) = *(float *)(param_3 + 0x44) * FLOAT_803e4490;
        uVar4 = 0;
      }
      else {
        *(float *)(param_2 + 8) = *(float *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x40) = fVar1;
        *(float *)(param_3 + 0x44) = fVar1;
        uVar4 = 1;
      }
    }
  }
  return uVar4;
}

