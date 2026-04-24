// Function: FUN_801636f0
// Entry: 801636f0
// Size: 452 bytes

void FUN_801636f0(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  short sVar2;
  short *psVar3;
  int iVar4;
  float *pfVar5;
  float *pfVar6;
  int unaff_r30;
  int iVar7;
  float *pfVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860d8();
  psVar3 = (short *)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  pfVar8 = *(float **)(psVar3 + 0x5c);
  *pfVar8 = FLOAT_803e2f48;
  *(ushort *)(pfVar8 + 2) = (ushort)*(byte *)(iVar4 + 0x1b) << 1;
  *(undefined *)(pfVar8 + 0x13) = *(undefined *)(iVar4 + 0x23);
  psVar3[2] = (*(byte *)(iVar4 + 0x18) - 0x7f) * 0x80;
  psVar3[1] = (*(byte *)(iVar4 + 0x19) - 0x7f) * 0x80;
  *psVar3 = (ushort)*(byte *)(iVar4 + 0x1a) << 8;
  *(undefined4 *)(psVar3 + 4) = *(undefined4 *)(iVar4 + 0x1c);
  fVar1 = *(float *)(psVar3 + 4);
  FUN_80035b50(psVar3,(int)(FLOAT_803e2f4c * fVar1),(int)(FLOAT_803e2f50 * fVar1),
               (int)(FLOAT_803e2f54 * fVar1));
  sVar2 = psVar3[0x23];
  if (sVar2 != 0x4b9) {
    if (sVar2 < 0x4b9) {
      if (sVar2 == 0x3fd) {
        *(undefined *)(pfVar8 + 0x14) = 3;
        unaff_r30 = 1;
        goto LAB_80163804;
      }
      if ((0x3fc < sVar2) || (sVar2 != 0x28d)) goto LAB_80163804;
    }
    else if (sVar2 != 0x4be) goto LAB_80163804;
  }
  *(undefined *)(pfVar8 + 0x14) = 3;
  unaff_r30 = 0;
LAB_80163804:
  if (param_3 == 0) {
    iVar7 = unaff_r30 * 0x30 + -0x7fcdfe18;
    pfVar5 = pfVar8;
    pfVar6 = pfVar8;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(pfVar8 + 0x14); iVar4 = iVar4 + 1) {
      pfVar6[3] = 0.0;
      FUN_80003494(pfVar5 + 7,iVar7,0xc);
      pfVar5[7] = pfVar5[7] * *(float *)(psVar3 + 4);
      pfVar5[8] = pfVar5[8] * *(float *)(psVar3 + 4);
      pfVar5[9] = pfVar5[9] * *(float *)(psVar3 + 4);
      FUN_80021ac8(psVar3,pfVar5 + 7);
      pfVar6 = pfVar6 + 1;
      iVar7 = iVar7 + 0xc;
      pfVar5 = pfVar5 + 3;
    }
  }
  FUN_80286124();
  return;
}

