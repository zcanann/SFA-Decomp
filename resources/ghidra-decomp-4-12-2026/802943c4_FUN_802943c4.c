// Function: FUN_802943c4
// Entry: 802943c4
// Size: 320 bytes

void FUN_802943c4(void)

{
  float fVar1;
  float fVar2;
  ushort uVar3;
  float *pfVar4;
  float *pfVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  undefined8 uVar8;
  undefined2 local_34;
  
  uVar8 = FUN_802867a8();
  pfVar4 = (float *)((ulonglong)uVar8 >> 0x20);
  pfVar5 = (float *)uVar8;
  dVar7 = extraout_f1;
  dVar6 = (double)FUN_80293424();
  fVar1 = (float)(dVar6 * dVar6);
  fVar2 = (float)(dVar6 * (double)(fVar1 * (FLOAT_803e89e4 * fVar1 + FLOAT_803e89e0) +
                                  FLOAT_803e89dc));
  fVar1 = fVar1 * (fVar1 * (FLOAT_803e89f4 * fVar1 + FLOAT_803e89f0) + FLOAT_803e89ec) +
          FLOAT_803e89e8;
  uVar3 = local_34 & 6;
  if (uVar3 == 2) {
    if (dVar7 < (double)FLOAT_803e89d8) {
      fVar1 = -fVar1;
    }
    *pfVar4 = fVar1;
    *pfVar5 = -fVar2;
  }
  else {
    if (uVar3 < 2) {
      if ((local_34 & 6) == 0) {
        if (dVar7 < (double)FLOAT_803e89d8) {
          fVar2 = -fVar2;
        }
        *pfVar4 = fVar2;
        *pfVar5 = fVar1;
        goto LAB_802944e8;
      }
    }
    else if (uVar3 == 4) {
      if ((double)FLOAT_803e89d8 <= dVar7) {
        fVar2 = -fVar2;
      }
      *pfVar4 = fVar2;
      *pfVar5 = -fVar1;
      goto LAB_802944e8;
    }
    if ((double)FLOAT_803e89d8 <= dVar7) {
      fVar1 = -fVar1;
    }
    *pfVar4 = fVar1;
    *pfVar5 = fVar2;
  }
LAB_802944e8:
  FUN_802867f4();
  return;
}

