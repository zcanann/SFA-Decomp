// Function: FUN_801bf5fc
// Entry: 801bf5fc
// Size: 652 bytes

void FUN_801bf5fc(ushort *param_1,int param_2)

{
  float fVar1;
  ushort uVar3;
  short sVar4;
  uint uVar2;
  int iVar5;
  char cVar6;
  float *pfVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_2 + 0x40c);
  pfVar7 = *(float **)(param_2 + 0x3dc);
  if ((*(ushort *)(param_2 + 0x400) & 8) == 0) {
    FUN_8002bac4();
    uVar2 = FUN_80021884();
    iVar8 = (uVar2 & 0xffff) - (uint)*param_1;
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    iVar8 = iVar8 * (uint)DAT_803dc070;
    *param_1 = *param_1 +
               ((short)((ulonglong)((longlong)iVar8 * 0x55555556) >> 0x20) -
               ((short)((short)(iVar8 / 0x30000) + (short)(iVar8 >> 0x1f)) >> 0xf));
  }
  else {
    iVar5 = FUN_80010340((double)*(float *)(iVar8 + 0x10),pfVar7);
    if (((iVar5 != 0) || (pfVar7[4] != 0.0)) &&
       (cVar6 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar7), cVar6 != '\0')) {
      *(ushort *)(param_2 + 0x400) = *(ushort *)(param_2 + 0x400) & 0xfff7;
    }
    iVar5 = FUN_80021884();
    uVar3 = (short)iVar5 + 0x8000;
    sVar4 = uVar3 - *param_1;
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    *param_1 = uVar3;
    iVar5 = (int)sVar4;
    *(float *)(iVar8 + 4) =
         *(float *)(iVar8 + 4) +
         (float)((double)CONCAT44(0x43300000,iVar5 >> 4 ^ 0x80000000) - DOUBLE_803e5990);
    if (*(float *)(iVar8 + 0x10) < FLOAT_803e59ac) {
      *(float *)(iVar8 + 0x10) = *(float *)(iVar8 + 0x10) + FLOAT_803e59b0;
    }
    iVar5 = iVar5 / 0xb6 + (iVar5 >> 0x1f);
    uVar2 = iVar5 - (iVar5 >> 0x1f);
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    fVar1 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5990) *
            FLOAT_803e596c;
    if (FLOAT_803e5988 < fVar1) {
      *(float *)(iVar8 + 0x10) = *(float *)(iVar8 + 0x10) / fVar1;
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) + FLOAT_803e59b4;
    }
    if (FLOAT_803e5970 < *(float *)(iVar8 + 8)) {
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) / FLOAT_803e59a8;
    }
    *(float *)(param_1 + 6) = pfVar7[0x1a];
    *(float *)(param_1 + 10) = pfVar7[0x1c];
  }
  return;
}

