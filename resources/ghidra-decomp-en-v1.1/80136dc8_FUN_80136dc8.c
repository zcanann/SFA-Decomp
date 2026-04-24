// Function: FUN_80136dc8
// Entry: 80136dc8
// Size: 960 bytes

uint FUN_80136dc8(undefined4 param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  
  if (param_2 < 0x40) {
    if (DAT_803de678 != 0) {
      if (DAT_803de68c != 0) {
        FUN_8004c460(DAT_803de6a4,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a4 + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a4 + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 0;
    }
    param_2 = param_2 + -0x21;
  }
  else if (param_2 < 0x60) {
    if (DAT_803de678 != 1) {
      if (DAT_803de68c != 0) {
        FUN_8004c460(DAT_803de6a0,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a0 + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a0 + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 1;
    }
    param_2 = param_2 + -0x40;
  }
  else if (param_2 < 0x80) {
    if (DAT_803de678 != 2) {
      if (DAT_803de68c != 0) {
        FUN_8004c460(DAT_803de69c,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de69c + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de69c + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 2;
    }
    param_2 = param_2 + -0x60;
  }
  iVar3 = DAT_803de678 * 0x40 + -0x7fce2410;
  uVar5 = (uint)*(byte *)(iVar3 + param_2 * 2);
  uVar4 = (*(byte *)(iVar3 + param_2 * 2 + 1) - uVar5) + 1;
  if (DAT_803de68c != 0) {
    uVar1 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803de69a) - DOUBLE_803e3038) *
                  (FLOAT_803de658 +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803de660) - DOUBLE_803e3038)));
    uVar2 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803de698) - DOUBLE_803e3038) *
                  (FLOAT_803de65c +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803de661) - DOUBLE_803e3038)));
    FUN_80078d98();
    FUN_80076008((double)((float)((double)CONCAT44(0x43300000,uVar5 << 5 ^ 0x80000000) -
                                 DOUBLE_803e3040) * FLOAT_803de66c),(double)FLOAT_803e3030,
                 (double)(FLOAT_803de66c *
                         (float)((double)CONCAT44(0x43300000,(uVar5 + uVar4) * 0x20 ^ 0x80000000) -
                                DOUBLE_803e3040)),(double)(FLOAT_803e3034 * FLOAT_803de668),
                 uVar1 << 2,uVar2 << 2,
                 (short)(int)(FLOAT_803e3028 *
                             ((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                     DOUBLE_803e3040) *
                              (FLOAT_803de658 +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803de660) -
                                     DOUBLE_803e3038)) +
                             (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                    DOUBLE_803e3040))),
                 (short)(int)(FLOAT_803e3028 *
                             (FLOAT_803e302c *
                              (FLOAT_803de65c +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803de661) -
                                     DOUBLE_803e3038)) +
                             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                    DOUBLE_803e3040))));
  }
  return uVar4;
}

