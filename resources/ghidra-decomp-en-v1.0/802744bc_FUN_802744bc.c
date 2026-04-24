// Function: FUN_802744bc
// Entry: 802744bc
// Size: 364 bytes

undefined4 FUN_802744bc(short *param_1,undefined4 param_2)

{
  short **ppsVar1;
  short *psVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  short *psVar6;
  ushort uVar7;
  ushort uVar8;
  ushort uVar9;
  
  uVar4 = 0;
  uVar5 = (uint)DAT_803de288;
  for (ppsVar1 = (short **)&DAT_803bfc78; ((int)uVar4 < (int)uVar5 && (*ppsVar1 != param_1));
      ppsVar1 = ppsVar1 + 3) {
    uVar4 = uVar4 + 1;
  }
  if (uVar4 == uVar5) {
    if (uVar5 < 0x80) {
      uVar9 = 0;
      for (psVar2 = param_1; *psVar2 != -1; psVar2 = psVar2 + 0x10) {
        uVar9 = uVar9 + 1;
      }
      FUN_80284af4();
      psVar2 = param_1;
      for (uVar7 = 0; uVar7 < uVar9; uVar7 = uVar7 + 1) {
        uVar5 = 0;
        ppsVar1 = (short **)&DAT_803bfc78;
        for (uVar4 = (uint)DAT_803de288; uVar4 != 0; uVar4 = uVar4 - 1) {
          psVar6 = *ppsVar1;
          for (uVar8 = 0; uVar8 < *(ushort *)(ppsVar1 + 2); uVar8 = uVar8 + 1) {
            if (*psVar2 == *psVar6) goto LAB_802745ac;
            psVar6 = psVar6 + 0x10;
          }
          ppsVar1 = ppsVar1 + 3;
          uVar5 = uVar5 + 1;
        }
LAB_802745ac:
        if (uVar5 == DAT_803de288) {
          psVar2[1] = 0;
        }
        else {
          psVar2[1] = -1;
        }
        psVar2 = psVar2 + 0x10;
      }
      uVar4 = (uint)DAT_803de288;
      (&DAT_803bfc78)[uVar4 * 3] = param_1;
      (&DAT_803bfc80)[uVar4 * 6] = uVar9;
      *(undefined4 *)(&DAT_803bfc7c + uVar4 * 0xc) = param_2;
      DAT_803de288 = DAT_803de288 + 1;
      FUN_80284abc();
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}

