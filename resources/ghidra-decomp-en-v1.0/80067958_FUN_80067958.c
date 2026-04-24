// Function: FUN_80067958
// Entry: 80067958
// Size: 556 bytes

void FUN_80067958(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 float *param_5)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined uVar4;
  float *pfVar5;
  float *pfVar6;
  short sVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860d4();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  if (4 < param_4) {
    param_4 = 4;
  }
  *(undefined2 *)(param_5 + 0x1b) = 0;
  fVar2 = FLOAT_803decc4;
  fVar1 = FLOAT_803decb4;
  sVar7 = 0;
  if (0 < param_4) {
    pfVar5 = param_5;
    pfVar6 = param_5;
    if (8 < param_4) {
      for (; (int)sVar7 < param_4 + -8; sVar7 = sVar7 + 8) {
        *pfVar5 = fVar1;
        pfVar5[1] = fVar2;
        pfVar5[2] = fVar1;
        pfVar5[3] = fVar1;
        pfVar6[0x17] = 0.0;
        pfVar5[4] = fVar1;
        pfVar5[5] = fVar2;
        pfVar5[6] = fVar1;
        pfVar5[7] = fVar1;
        pfVar6[0x18] = 0.0;
        pfVar5[8] = fVar1;
        pfVar5[9] = fVar2;
        pfVar5[10] = fVar1;
        pfVar5[0xb] = fVar1;
        pfVar6[0x19] = 0.0;
        pfVar5[0xc] = fVar1;
        pfVar5[0xd] = fVar2;
        pfVar5[0xe] = fVar1;
        pfVar5[0xf] = fVar1;
        pfVar6[0x1a] = 0.0;
        pfVar5[0x10] = fVar1;
        pfVar5[0x11] = fVar2;
        pfVar5[0x12] = fVar1;
        pfVar5[0x13] = fVar1;
        pfVar6[0x1b] = 0.0;
        pfVar5[0x14] = fVar1;
        pfVar5[0x15] = fVar2;
        pfVar5[0x16] = fVar1;
        pfVar5[0x17] = fVar1;
        pfVar6[0x1c] = 0.0;
        pfVar5[0x18] = fVar1;
        pfVar5[0x19] = fVar2;
        pfVar5[0x1a] = fVar1;
        pfVar5[0x1b] = fVar1;
        pfVar6[0x1d] = 0.0;
        pfVar5[0x1c] = fVar1;
        pfVar5[0x1d] = fVar2;
        pfVar5[0x1e] = fVar1;
        pfVar5[0x1f] = fVar1;
        pfVar6[0x1e] = 0.0;
        pfVar5 = pfVar5 + 0x20;
        pfVar6 = pfVar6 + 8;
      }
    }
    fVar2 = FLOAT_803decc4;
    fVar1 = FLOAT_803decb4;
    pfVar5 = param_5 + sVar7 * 4;
    pfVar6 = param_5 + sVar7;
    for (; sVar7 < param_4; sVar7 = sVar7 + 1) {
      *pfVar5 = fVar1;
      pfVar5[1] = fVar2;
      pfVar5[2] = fVar1;
      pfVar5[3] = fVar1;
      pfVar6[0x17] = 0.0;
      pfVar5 = pfVar5 + 4;
      pfVar6 = pfVar6 + 1;
    }
  }
  uVar4 = FUN_800667ec(0,DAT_803dcf30 + DAT_8038dc68 * 0x4c,DAT_803dcf30 + DAT_8038dc80 * 0x4c,
                       (int)uVar8,param_3,param_4,param_5,0);
  pfVar5 = param_5;
  pfVar6 = param_5;
  for (sVar7 = 0; sVar7 < param_4; sVar7 = sVar7 + 1) {
    if ((pfVar6[0x17] != 0.0) && (FUN_8002b198(pfVar6[0x17],pfVar5,pfVar5), iVar3 != 0)) {
      FUN_80036708(pfVar6[0x17],iVar3);
    }
    pfVar6 = pfVar6 + 1;
    pfVar5 = pfVar5 + 4;
  }
  *(undefined *)((int)param_5 + 0x6e) = uVar4;
  FUN_80286120(uVar4);
  return;
}

