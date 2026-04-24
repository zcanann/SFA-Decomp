// Function: FUN_802935ac
// Entry: 802935ac
// Size: 416 bytes

void FUN_802935ac(void)

{
  uint uVar1;
  double dVar2;
  double dVar3;
  undefined2 local_26 [5];
  
  uVar1 = FUN_8028604c();
  local_26[0] = (undefined2)(uVar1 << 2);
  dVar2 = (double)FUN_80291e08(local_26);
  dVar2 = DOUBLE_803e7cd0 * dVar2;
  dVar3 = dVar2 * dVar2;
  uVar1 = uVar1 & 0xe000;
  if (uVar1 != 0x6000) {
    if (uVar1 < 0x6000) {
      if (uVar1 == 0x2000) {
LAB_80293680:
        dVar2 = (double)(float)(dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (DOUBLE_803e7d38 * dVar3
                                                                            + DOUBLE_803e7d30) +
                                                                   DOUBLE_803e7d28) +
                                                          DOUBLE_803e7d20) + DOUBLE_803e7d18) +
                                        DOUBLE_803e7d10) + DOUBLE_803e7d08);
      }
      else {
        if (uVar1 < 0x2000) {
          if (uVar1 == 0) goto LAB_80293648;
        }
        else if (uVar1 == 0x4000) goto LAB_80293680;
LAB_802936f8:
        dVar2 = (double)(float)-(dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (DOUBLE_803e7d38 *
                                                                              dVar3 + 
                                                  DOUBLE_803e7d30) + DOUBLE_803e7d28) +
                                                  DOUBLE_803e7d20) + DOUBLE_803e7d18) +
                                         DOUBLE_803e7d10) + DOUBLE_803e7d08);
      }
      goto LAB_80293730;
    }
    if (uVar1 == 0xe000) {
LAB_80293648:
      dVar2 = (double)(float)(dVar2 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (DOUBLE_803e7d00 * dVar3 +
                                                                          DOUBLE_803e7cf8) +
                                                                 DOUBLE_803e7cf0) + DOUBLE_803e7ce8)
                                               + DOUBLE_803e7ce0) + DOUBLE_803e7cd8));
      goto LAB_80293730;
    }
    if ((0xdfff < uVar1) || (uVar1 != 0x8000)) goto LAB_802936f8;
  }
  dVar2 = (double)(float)-(dVar2 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (DOUBLE_803e7d00 * dVar3 +
                                                                       DOUBLE_803e7cf8) +
                                                              DOUBLE_803e7cf0) + DOUBLE_803e7ce8) +
                                            DOUBLE_803e7ce0) + DOUBLE_803e7cd8));
LAB_80293730:
  FUN_80286098(dVar2);
  return;
}

