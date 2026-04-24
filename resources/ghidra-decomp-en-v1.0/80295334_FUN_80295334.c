// Function: FUN_80295334
// Entry: 80295334
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x80295374) */

void FUN_80295334(double param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6)

{
  double dVar1;
  undefined auStack120 [48];
  undefined auStack72 [48];
  undefined4 local_18;
  uint uStack20;
  
  if (DAT_803dc66c == 3) {
    FLOAT_803dc670 = FLOAT_803e7e80;
    FLOAT_803dc674 = FLOAT_803e7e84;
    FLOAT_803dc678 = FLOAT_803e7e88;
    uStack20 = param_6 ^ 0x80000000;
    local_18 = 0x43300000;
    dVar1 = (double)FUN_802943f4((double)(float)((double)FLOAT_803e7eb4 * param_1 -
                                                (double)(FLOAT_803e7eb8 *
                                                        (float)((double)CONCAT44(0x43300000,uStack20
                                                                                ) - DOUBLE_803e7ec0)
                                                        )));
    FUN_802470c8((double)(float)((double)FLOAT_803e7eb4 * dVar1),auStack72,0x79);
    if (param_6 == 1) {
      FUN_802470c8((double)FLOAT_803e7ebc,auStack120,0x78);
      FUN_80246eb4(auStack120,auStack72,auStack72);
    }
    FUN_80247574(auStack72,param_4,param_4);
  }
  else if (DAT_803dc66c < 3) {
    if (DAT_803dc66c == 1) {
      FLOAT_803dc670 = FLOAT_803e7e80;
      FLOAT_803dc674 = FLOAT_803e7e84;
      FLOAT_803dc678 = FLOAT_803e7e88;
      uStack20 = param_6 ^ 0x80000000;
      local_18 = 0x43300000;
      dVar1 = (double)FUN_802943f4((double)(float)((double)FLOAT_803e7e90 * param_1 -
                                                  (double)(FLOAT_803e7e94 *
                                                          (float)((double)CONCAT44(0x43300000,
                                                                                   uStack20) -
                                                                 DOUBLE_803e7ec0))));
      FUN_802470c8((double)(float)((double)FLOAT_803e7e8c * dVar1),auStack72,0x79);
      FUN_80247574(auStack72,param_4,param_4);
    }
    else if (DAT_803dc66c == 0) {
      FLOAT_803dc670 = FLOAT_803e7e80;
      FLOAT_803dc674 = FLOAT_803e7e84;
      FLOAT_803dc678 = FLOAT_803e7e88;
    }
    else {
      FLOAT_803dc670 = FLOAT_803e7ea0;
      FLOAT_803dc674 = FLOAT_803e7ea4;
      FLOAT_803dc678 = FLOAT_803e7ea8;
      dVar1 = (double)FUN_802943f4((double)(float)((double)FLOAT_803e7e98 * param_1));
      FUN_802470c8((double)(float)((double)FLOAT_803e7eac * dVar1),auStack72,0x79);
      FUN_802470c8((double)FLOAT_803e7eb0,auStack120,0x78);
      FUN_80246eb4(auStack120,auStack72,auStack72);
      FUN_80247574(auStack72,param_4,param_4);
    }
  }
  else if (DAT_803dc66c == 5) {
    FLOAT_803dc670 = FLOAT_803e7e9c;
    FLOAT_803dc674 = FLOAT_803e7e84;
    FLOAT_803dc678 = FLOAT_803e7e88;
    uStack20 = param_6 ^ 0x80000000;
    local_18 = 0x43300000;
    dVar1 = (double)FUN_802943f4((double)(float)((double)FLOAT_803e7e90 * param_1 -
                                                (double)(FLOAT_803e7e94 *
                                                        (float)((double)CONCAT44(0x43300000,uStack20
                                                                                ) - DOUBLE_803e7ec0)
                                                        )));
    FUN_802470c8((double)(float)((double)FLOAT_803e7e8c * dVar1),auStack72,0x79);
    FUN_80247574(auStack72,param_4,param_4);
  }
  else if (DAT_803dc66c < 5) {
    FLOAT_803dc670 = FLOAT_803e7e98;
    FLOAT_803dc674 = FLOAT_803e7e84;
    FLOAT_803dc678 = FLOAT_803e7e88;
    uStack20 = param_6 ^ 0x80000000;
    local_18 = 0x43300000;
    dVar1 = (double)FUN_802943f4((double)(float)((double)FLOAT_803e7e90 * param_1 -
                                                (double)(FLOAT_803e7e94 *
                                                        (float)((double)CONCAT44(0x43300000,uStack20
                                                                                ) - DOUBLE_803e7ec0)
                                                        )));
    FUN_802470c8((double)(float)((double)FLOAT_803e7e8c * dVar1),auStack72,0x79);
    FUN_80247574(auStack72,param_4,param_4);
  }
  return;
}

