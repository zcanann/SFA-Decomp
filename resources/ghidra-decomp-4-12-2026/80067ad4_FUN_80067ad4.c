// Function: FUN_80067ad4
// Entry: 80067ad4
// Size: 556 bytes

void FUN_80067ad4(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined uVar4;
  int in_r6;
  float *pfVar5;
  float *in_r7;
  float *pfVar6;
  short sVar7;
  
  iVar3 = FUN_80286838();
  if (4 < in_r6) {
    in_r6 = 4;
  }
  *(undefined2 *)(in_r7 + 0x1b) = 0;
  fVar2 = FLOAT_803df944;
  fVar1 = FLOAT_803df934;
  sVar7 = 0;
  if (0 < in_r6) {
    pfVar5 = in_r7;
    pfVar6 = in_r7;
    if (8 < in_r6) {
      for (; (int)sVar7 < in_r6 + -8; sVar7 = sVar7 + 8) {
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
    fVar2 = FLOAT_803df944;
    fVar1 = FLOAT_803df934;
    pfVar5 = in_r7 + sVar7 * 4;
    pfVar6 = in_r7 + sVar7;
    for (; sVar7 < in_r6; sVar7 = sVar7 + 1) {
      *pfVar5 = fVar1;
      pfVar5[1] = fVar2;
      pfVar5[2] = fVar1;
      pfVar5[3] = fVar1;
      pfVar6[0x17] = 0.0;
      pfVar5 = pfVar5 + 4;
      pfVar6 = pfVar6 + 1;
    }
  }
  uVar4 = FUN_80066968();
  pfVar5 = in_r7;
  pfVar6 = in_r7;
  for (sVar7 = 0; sVar7 < in_r6; sVar7 = sVar7 + 1) {
    if (((ushort *)pfVar6[0x17] != (ushort *)0x0) &&
       (FUN_8002b270((ushort *)pfVar6[0x17],pfVar5,pfVar5), iVar3 != 0)) {
      FUN_80036800((int)pfVar6[0x17],iVar3);
    }
    pfVar6 = pfVar6 + 1;
    pfVar5 = pfVar5 + 4;
  }
  *(undefined *)((int)in_r7 + 0x6e) = uVar4;
  FUN_80286884();
  return;
}

