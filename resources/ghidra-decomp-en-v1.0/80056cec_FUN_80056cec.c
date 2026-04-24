// Function: FUN_80056cec
// Entry: 80056cec
// Size: 224 bytes

void FUN_80056cec(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  short *psVar2;
  short extraout_r4;
  uint uVar3;
  uint uVar4;
  
  uVar1 = FUN_802860dc();
  uVar3 = 0;
  uVar4 = (uint)DAT_803dce98;
  for (psVar2 = DAT_803dce94; (uVar4 != 0 && (*psVar2 != -1)); psVar2 = psVar2 + 1) {
    uVar3 = uVar3 + 1;
    uVar4 = uVar4 - 1;
  }
  if ((uVar3 == DAT_803dce98) && (DAT_803dce98 = DAT_803dce98 + 1, DAT_803dce98 == 0x40)) {
    FUN_8007d6dc(s_trackLoadBlockEnd__track_block_o_8030e768);
  }
  *(char *)((&DAT_803822b4)[param_4] + param_3) = (char)uVar3;
  *(undefined4 *)(DAT_803dce9c + uVar3 * 4) = uVar1;
  DAT_803dce94[uVar3] = extraout_r4;
  *(undefined *)(DAT_803dce8c + uVar3) = 1;
  FUN_80065678();
  FUN_80286128();
  return;
}

