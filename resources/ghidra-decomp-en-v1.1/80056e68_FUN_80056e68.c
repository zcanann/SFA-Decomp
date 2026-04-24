// Function: FUN_80056e68
// Entry: 80056e68
// Size: 224 bytes

void FUN_80056e68(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  short *psVar2;
  short extraout_r4;
  uint uVar3;
  uint uVar4;
  
  uVar1 = FUN_80286840();
  uVar3 = 0;
  uVar4 = (uint)DAT_803ddb18;
  for (psVar2 = DAT_803ddb14; (uVar4 != 0 && (*psVar2 != -1)); psVar2 = psVar2 + 1) {
    uVar3 = uVar3 + 1;
    uVar4 = uVar4 - 1;
  }
  if ((uVar3 == DAT_803ddb18) && (DAT_803ddb18 = DAT_803ddb18 + 1, DAT_803ddb18 == 0x40)) {
    FUN_8007d858();
  }
  *(char *)((&DAT_80382f14)[param_4] + param_3) = (char)uVar3;
  *(undefined4 *)(DAT_803ddb1c + uVar3 * 4) = uVar1;
  DAT_803ddb14[uVar3] = extraout_r4;
  *(undefined *)(DAT_803ddb0c + uVar3) = 1;
  FUN_800657f4();
  FUN_8028688c();
  return;
}

