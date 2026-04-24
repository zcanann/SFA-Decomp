// Function: FUN_800dbe30
// Entry: 800dbe30
// Size: 344 bytes

undefined4 FUN_800dbe30(float *param_1)

{
  int iVar1;
  undefined4 uVar2;
  short *psVar3;
  short *psVar4;
  short *psVar5;
  short *psVar6;
  short sVar7;
  short sVar8;
  
  iVar1 = FUN_800dc27c(param_1);
  if (iVar1 == 0) {
    psVar6 = &DAT_8039d778;
    for (sVar8 = 1; sVar8 < DAT_803de0e4; sVar8 = sVar8 + 1) {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,(int)psVar6[0x10] ^ 0x80000000) - DOUBLE_803e1260))
         && ((float)((double)CONCAT44(0x43300000,(int)psVar6[0x11] ^ 0x80000000) - DOUBLE_803e1260)
             < param_1[1])) {
        sVar7 = 0;
        psVar3 = psVar6;
        psVar4 = psVar6;
        for (psVar5 = psVar6;
            (sVar7 < 4 &&
            (*(float *)(psVar5 + 8) +
             *param_1 *
             (float)((double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000) - DOUBLE_803e1260) +
             param_1[2] *
             (float)((double)CONCAT44(0x43300000,(int)psVar3[1] ^ 0x80000000) - DOUBLE_803e1260) <=
             FLOAT_803e1270)); psVar5 = psVar5 + 2) {
          sVar7 = sVar7 + 1;
          psVar3 = psVar3 + 2;
          psVar4 = psVar4 + 2;
        }
        if (sVar7 == 4) {
          return 1;
        }
      }
      psVar6 = psVar6 + 0x18;
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

