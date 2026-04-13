// Function: FUN_8016f4d4
// Entry: 8016f4d4
// Size: 324 bytes

void FUN_8016f4d4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  short *psVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined8 extraout_f1;
  
  psVar2 = &DAT_803214f0;
  iVar4 = 5;
  do {
    if (*psVar2 == 0) {
      *psVar2 = 0xc3;
    }
    if (psVar2[1] == 0) {
      psVar2[1] = 0xc3;
    }
    if (psVar2[2] == 0) {
      psVar2[2] = 0xc3;
    }
    if (psVar2[3] == 0) {
      psVar2[3] = 0xc3;
    }
    if (psVar2[4] == 0) {
      psVar2[4] = 0xc3;
    }
    if (psVar2[5] == 0) {
      psVar2[5] = 0xc3;
    }
    if (psVar2[6] == 0) {
      psVar2[6] = 0xc3;
    }
    psVar2 = psVar2 + 7;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  DAT_803de724 = &DAT_803dc9b8;
  if (DAT_803de728 == 0) {
    iVar4 = 0;
    puVar3 = &DAT_803de728;
    do {
      uVar1 = FUN_80054620(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      *puVar3 = uVar1;
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      param_1 = extraout_f1;
    } while (iVar4 < 2);
  }
  if (DAT_803de720 == 0) {
    DAT_803de720 = FUN_80013ee8(0x5a);
  }
  return;
}

