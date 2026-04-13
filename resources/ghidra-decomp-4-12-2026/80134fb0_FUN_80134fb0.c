// Function: FUN_80134fb0
// Entry: 80134fb0
// Size: 280 bytes

void FUN_80134fb0(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char param_9)

{
  ushort *puVar1;
  undefined *puVar2;
  undefined8 uVar3;
  double dVar4;
  double dVar5;
  
  if (param_9 == '\0') {
    if (DAT_803de620 == '\0') {
      FLOAT_803de61c = FLOAT_803e2fa8;
      param_1 = (double)FLOAT_803de634;
      if ((double)FLOAT_803e2fac < param_1) {
        DAT_803de620 = '\x01';
      }
    }
    else {
      FLOAT_803de61c = FLOAT_803de634;
    }
  }
  else {
    FLOAT_803de61c = FLOAT_803e2fa8;
    DAT_803de620 = '\0';
  }
  puVar1 = FUN_800195a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3d9);
  if (*puVar1 != 0xffff) {
    puVar2 = FUN_80017400((uint)*(byte *)(puVar1 + 2));
    if (DAT_803de62c == 0) {
      DAT_803de62c = (uint)*(short *)(puVar2 + 0x16);
    }
    dVar5 = (double)FLOAT_803e2fb0;
    dVar4 = (double)(FLOAT_803e2fa8 - FLOAT_803de61c);
    *(short *)(puVar2 + 0x16) =
         (short)(int)(dVar5 * dVar4 +
                     (double)(float)((double)CONCAT44(0x43300000,DAT_803de62c ^ 0x80000000) -
                                    DOUBLE_803e2f78));
    uVar3 = FUN_80019940(0xff,0xff,0xff,(byte)(int)(FLOAT_803e2fb4 * FLOAT_803de630));
    FUN_800168a8(uVar3,dVar4,dVar5,param_4,param_5,param_6,param_7,param_8,0x3d9);
  }
  return;
}

