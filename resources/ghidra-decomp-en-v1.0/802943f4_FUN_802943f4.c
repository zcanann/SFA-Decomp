// Function: FUN_802943f4
// Entry: 802943f4
// Size: 344 bytes

void FUN_802943f4(void)

{
  double dVar1;
  double dVar2;
  uint local_14 [5];
  
  dVar1 = (double)FUN_80286050();
  dVar1 = (double)FUN_80292d3c((double)(float)dVar1,local_14);
  dVar2 = dVar1 * dVar1;
  local_14[0] = local_14[0] & 6;
  if (local_14[0] == 2) {
    dVar1 = (double)(float)-(dVar1 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7dd8 * dVar2 +
                                                                         DOUBLE_803e7dd0) +
                                                                DOUBLE_803e7dc8) + DOUBLE_803e7dc0)
                                              + DOUBLE_803e7db8) + DOUBLE_803e7db0));
  }
  else {
    if (local_14[0] < 2) {
      if (local_14[0] == 0) {
        dVar1 = (double)(float)(dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7e10 * dVar2
                                                                            + DOUBLE_803e7e08) +
                                                                   DOUBLE_803e7e00) +
                                                          DOUBLE_803e7df8) + DOUBLE_803e7df0) +
                                        DOUBLE_803e7de8) + DOUBLE_803e7de0);
        goto LAB_80294534;
      }
    }
    else if (local_14[0] == 4) {
      dVar1 = (double)(float)-(dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7e10 * dVar2
                                                                           + DOUBLE_803e7e08) +
                                                                  DOUBLE_803e7e00) + DOUBLE_803e7df8
                                                         ) + DOUBLE_803e7df0) + DOUBLE_803e7de8) +
                              DOUBLE_803e7de0);
      goto LAB_80294534;
    }
    dVar1 = (double)(float)(dVar1 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (DOUBLE_803e7dd8 * dVar2 +
                                                                        DOUBLE_803e7dd0) +
                                                               DOUBLE_803e7dc8) + DOUBLE_803e7dc0) +
                                             DOUBLE_803e7db8) + DOUBLE_803e7db0));
  }
LAB_80294534:
  FUN_8028609c(dVar1);
  return;
}

