// Function: FUN_80136a40
// Entry: 80136a40
// Size: 960 bytes

uint FUN_80136a40(undefined4 param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  
  if (param_2 < 0x40) {
    if (DAT_803dd9f8 != 0) {
      if (DAT_803dda0c != 0) {
        FUN_8004c2e4(DAT_803dda24,0);
        FLOAT_803dd9ec =
             FLOAT_803e2390 /
             (FLOAT_803e2394 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dda24 + 10)) -
                    DOUBLE_803e23a8));
        FLOAT_803dd9e8 =
             FLOAT_803e2390 /
             (FLOAT_803e2394 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dda24 + 0xc)) -
                    DOUBLE_803e23a8));
      }
      DAT_803dd9f8 = 0;
    }
    param_2 = param_2 + -0x21;
  }
  else if (param_2 < 0x60) {
    if (DAT_803dd9f8 != 1) {
      if (DAT_803dda0c != 0) {
        FUN_8004c2e4(DAT_803dda20,0);
        FLOAT_803dd9ec =
             FLOAT_803e2390 /
             (FLOAT_803e2394 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dda20 + 10)) -
                    DOUBLE_803e23a8));
        FLOAT_803dd9e8 =
             FLOAT_803e2390 /
             (FLOAT_803e2394 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dda20 + 0xc)) -
                    DOUBLE_803e23a8));
      }
      DAT_803dd9f8 = 1;
    }
    param_2 = param_2 + -0x40;
  }
  else if (param_2 < 0x80) {
    if (DAT_803dd9f8 != 2) {
      if (DAT_803dda0c != 0) {
        FUN_8004c2e4(DAT_803dda1c,0);
        FLOAT_803dd9ec =
             FLOAT_803e2390 /
             (FLOAT_803e2394 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dda1c + 10)) -
                    DOUBLE_803e23a8));
        FLOAT_803dd9e8 =
             FLOAT_803e2390 /
             (FLOAT_803e2394 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dda1c + 0xc)) -
                    DOUBLE_803e23a8));
      }
      DAT_803dd9f8 = 2;
    }
    param_2 = param_2 + -0x60;
  }
  iVar3 = DAT_803dd9f8 * 0x40 + -0x7fce3060;
  uVar5 = (uint)*(byte *)(iVar3 + param_2 * 2);
  uVar4 = (*(byte *)(iVar3 + param_2 * 2 + 1) - uVar5) + 1;
  if (DAT_803dda0c != 0) {
    uVar1 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803dda1a) - DOUBLE_803e23a8) *
                  (FLOAT_803dd9d8 +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803dd9e0) - DOUBLE_803e23a8)));
    uVar2 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803dda18) - DOUBLE_803e23a8) *
                  (FLOAT_803dd9dc +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803dd9e1) - DOUBLE_803e23a8)));
    FUN_80078c1c();
    FUN_80075e8c((double)((float)((double)CONCAT44(0x43300000,uVar5 << 5 ^ 0x80000000) -
                                 DOUBLE_803e23b0) * FLOAT_803dd9ec),(double)FLOAT_803e23a0,
                 (double)(FLOAT_803dd9ec *
                         (float)((double)CONCAT44(0x43300000,(uVar5 + uVar4) * 0x20 ^ 0x80000000) -
                                DOUBLE_803e23b0)),(double)(FLOAT_803e23a4 * FLOAT_803dd9e8),
                 uVar1 << 2,uVar2 << 2,
                 (int)(FLOAT_803e2398 *
                      ((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e23b0) *
                       (FLOAT_803dd9d8 +
                       (float)((double)CONCAT44(0x43300000,(uint)DAT_803dd9e0) - DOUBLE_803e23a8)) +
                      (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e23b0))),
                 (int)(FLOAT_803e2398 *
                      (FLOAT_803e239c *
                       (FLOAT_803dd9dc +
                       (float)((double)CONCAT44(0x43300000,(uint)DAT_803dd9e1) - DOUBLE_803e23a8)) +
                      (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e23b0))));
  }
  return uVar4;
}

