// Function: FUN_80163b9c
// Entry: 80163b9c
// Size: 452 bytes

void FUN_80163b9c(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  ushort uVar2;
  ushort *puVar3;
  int iVar4;
  float *pfVar5;
  float *pfVar6;
  int unaff_r30;
  uint uVar7;
  float *pfVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  pfVar8 = *(float **)(puVar3 + 0x5c);
  *pfVar8 = FLOAT_803e3be0;
  *(ushort *)(pfVar8 + 2) = (ushort)*(byte *)(iVar4 + 0x1b) << 1;
  *(undefined *)(pfVar8 + 0x13) = *(undefined *)(iVar4 + 0x23);
  puVar3[2] = (*(byte *)(iVar4 + 0x18) - 0x7f) * 0x80;
  puVar3[1] = (*(byte *)(iVar4 + 0x19) - 0x7f) * 0x80;
  *puVar3 = (ushort)*(byte *)(iVar4 + 0x1a) << 8;
  *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar4 + 0x1c);
  fVar1 = *(float *)(puVar3 + 4);
  FUN_80035c48((int)puVar3,(short)(int)(FLOAT_803e3be4 * fVar1),(short)(int)(FLOAT_803e3be8 * fVar1)
               ,(short)(int)(FLOAT_803e3bec * fVar1));
  uVar2 = puVar3[0x23];
  if (uVar2 != 0x4b9) {
    if ((short)uVar2 < 0x4b9) {
      if (uVar2 == 0x3fd) {
        *(undefined *)(pfVar8 + 0x14) = 3;
        unaff_r30 = 1;
        goto LAB_80163cb0;
      }
      if ((0x3fc < (short)uVar2) || (uVar2 != 0x28d)) goto LAB_80163cb0;
    }
    else if (uVar2 != 0x4be) goto LAB_80163cb0;
  }
  *(undefined *)(pfVar8 + 0x14) = 3;
  unaff_r30 = 0;
LAB_80163cb0:
  if (param_3 == 0) {
    uVar7 = unaff_r30 * 0x30 + 0x80320e38;
    pfVar5 = pfVar8;
    pfVar6 = pfVar8;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(pfVar8 + 0x14); iVar4 = iVar4 + 1) {
      pfVar6[3] = 0.0;
      FUN_80003494((uint)(pfVar5 + 7),uVar7,0xc);
      pfVar5[7] = pfVar5[7] * *(float *)(puVar3 + 4);
      pfVar5[8] = pfVar5[8] * *(float *)(puVar3 + 4);
      pfVar5[9] = pfVar5[9] * *(float *)(puVar3 + 4);
      FUN_80021b8c(puVar3,pfVar5 + 7);
      pfVar6 = pfVar6 + 1;
      uVar7 = uVar7 + 0xc;
      pfVar5 = pfVar5 + 3;
    }
  }
  FUN_80286888();
  return;
}

