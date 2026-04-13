// Function: FUN_8012ecb8
// Entry: 8012ecb8
// Size: 452 bytes

void FUN_8012ecb8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  ushort *puVar2;
  
  FUN_8002bac4();
  if (DAT_803de428 == '\0') {
    DAT_803de550 = DAT_803de550 + (ushort)DAT_803dc070 * -8;
    if (DAT_803de550 < 0) {
      DAT_803de550 = 0;
    }
  }
  else {
    if (DAT_803de548 != '\0') {
      (**(code **)(*DAT_803dd6d0 + 0x5c))(0x41,1);
    }
    DAT_803de550 = 0xff;
  }
  if (DAT_803de550 == 0) {
    DAT_803dc6d8 = 0xffff;
  }
  else if ((int)DAT_803de54a == 0xffffffff) {
    uVar1 = FUN_80014e9c(0);
    DAT_803aa0ac = (int)((uVar1 & 0x100) != 0);
    if (DAT_803aa0a8 == 1) {
      FUN_80014b68(0,0x100);
      DAT_803de524 = DAT_803de524 & 0xfffffeff;
      DAT_803de428 = '\0';
      if (DAT_803de429 != '\0') {
        FUN_800207ac(0);
        DAT_803de429 = '\0';
      }
    }
    if (DAT_803de428 != '\0') {
      FUN_80014b38();
    }
  }
  else {
    FLOAT_803de54c = FLOAT_803de54c - FLOAT_803dc074;
    if (FLOAT_803de54c <= FLOAT_803e2abc) {
      FLOAT_803de54c =
           (float)((double)CONCAT44(0x43300000,(int)DAT_803de54a ^ 0x80000000) - DOUBLE_803e2af8);
      DAT_803aa0a4 = DAT_803aa0a4 + 1;
      puVar2 = FUN_800195a8(DOUBLE_803e2af8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (uint)DAT_803dc6d8);
      if ((int)(uint)puVar2[1] <= DAT_803aa0a4) {
        DAT_803aa0a4 = puVar2[1] - 1;
        DAT_803de428 = '\0';
      }
    }
  }
  return;
}

