// Function: FUN_8012162c
// Entry: 8012162c
// Size: 192 bytes

void FUN_8012162c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined **ppuVar1;
  short *psVar2;
  undefined *puVar3;
  undefined4 uVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined6 uVar6;
  
  uVar6 = FUN_80286840();
  ppuVar1 = &PTR_DAT_8031c228;
  puVar3 = &DAT_803b0000;
  DAT_803a9ff8 = 0;
  uVar4 = param_11;
  uVar5 = extraout_f1;
  do {
    psVar2 = (short *)*ppuVar1;
    if (psVar2 == (short *)0x0) {
      if (DAT_803a9ff8 != 0) {
        DAT_803aa004 = (undefined2)param_11;
        DAT_803aa000 = FLOAT_803e2abc;
        DAT_803a9ffc = (int)uVar6;
      }
      FUN_8028688c();
      return;
    }
    for (; *psVar2 != -1; psVar2 = psVar2 + 8) {
      if (*psVar2 == (short)((uint6)uVar6 >> 0x20)) {
        DAT_803a9ff8 = FUN_80054ed0(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    (int)psVar2[3],puVar3,uVar4,param_12,param_13,param_14,param_15,
                                    param_16);
        break;
      }
    }
    ppuVar1 = ppuVar1 + 4;
  } while( true );
}

