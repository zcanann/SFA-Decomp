// Function: FUN_80294098
// Entry: 80294098
// Size: 364 bytes

void FUN_80294098(void)

{
  uint uVar1;
  double dVar2;
  double dVar3;
  uint local_14 [5];
  
  dVar2 = (double)FUN_80286050();
  dVar3 = (double)FUN_80292d3c((double)(float)dVar2,local_14);
  local_14[0] = local_14[0] + ((uint)(float)dVar2 >> 0x1d & 4);
  dVar2 = dVar3 * dVar3;
  uVar1 = local_14[0] & 6;
  if (uVar1 == 2) {
    dVar2 = (double)(float)(dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7e10 * dVar2 +
                                                                        DOUBLE_803e7e08) +
                                                               DOUBLE_803e7e00) + DOUBLE_803e7df8) +
                                             DOUBLE_803e7df0) + DOUBLE_803e7de8) + DOUBLE_803e7de0);
  }
  else {
    if (uVar1 < 2) {
      if (uVar1 == 0) {
        dVar2 = (double)(float)(dVar3 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7dd8 * dVar2
                                                                            + DOUBLE_803e7dd0) +
                                                                   DOUBLE_803e7dc8) +
                                                          DOUBLE_803e7dc0) + DOUBLE_803e7db8) +
                                        DOUBLE_803e7db0));
        goto LAB_802941ec;
      }
    }
    else if (uVar1 == 4) {
      dVar2 = (double)(float)-(dVar3 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7dd8 * dVar2
                                                                           + DOUBLE_803e7dd0) +
                                                                  DOUBLE_803e7dc8) + DOUBLE_803e7dc0
                                                         ) + DOUBLE_803e7db8) + DOUBLE_803e7db0));
      goto LAB_802941ec;
    }
    dVar2 = (double)(float)-(dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7e10 * dVar2 +
                                                                         DOUBLE_803e7e08) +
                                                                DOUBLE_803e7e00) + DOUBLE_803e7df8)
                                              + DOUBLE_803e7df0) + DOUBLE_803e7de8) +
                            DOUBLE_803e7de0);
  }
LAB_802941ec:
  FUN_8028609c(dVar2);
  return;
}

