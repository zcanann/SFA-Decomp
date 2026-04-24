// Function: FUN_801bf048
// Entry: 801bf048
// Size: 652 bytes

void FUN_801bf048(short *param_1,int param_2)

{
  float fVar1;
  short sVar3;
  uint uVar2;
  int iVar4;
  char cVar6;
  short sVar5;
  int iVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_2 + 0x40c);
  iVar7 = *(int *)(param_2 + 0x3dc);
  if ((*(ushort *)(param_2 + 0x400) & 8) == 0) {
    iVar7 = FUN_8002b9ec();
    uVar2 = FUN_800217c0(-(double)(*(float *)(iVar7 + 0x18) - *(float *)(param_1 + 0xc)),
                         -(double)(*(float *)(iVar7 + 0x20) - *(float *)(param_1 + 0x10)));
    iVar7 = (uVar2 & 0xffff) - ((int)*param_1 & 0xffffU);
    if (0x8000 < iVar7) {
      iVar7 = iVar7 + -0xffff;
    }
    if (iVar7 < -0x8000) {
      iVar7 = iVar7 + 0xffff;
    }
    iVar7 = iVar7 * (uint)DAT_803db410;
    *param_1 = *param_1 +
               ((short)((ulonglong)((longlong)iVar7 * 0x55555556) >> 0x20) -
               ((short)((short)(iVar7 / 0x30000) + (short)(iVar7 >> 0x1f)) >> 0xf));
  }
  else {
    iVar4 = FUN_80010320((double)*(float *)(iVar8 + 0x10),iVar7);
    if (((iVar4 != 0) || (*(int *)(iVar7 + 0x10) != 0)) &&
       (cVar6 = (**(code **)(*DAT_803dca9c + 0x90))(iVar7), cVar6 != '\0')) {
      *(ushort *)(param_2 + 0x400) = *(ushort *)(param_2 + 0x400) & 0xfff7;
    }
    sVar5 = FUN_800217c0((double)*(float *)(iVar7 + 0x74),(double)*(float *)(iVar7 + 0x7c));
    sVar3 = (sVar5 + -0x8000) - *param_1;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    *param_1 = sVar5 + -0x8000;
    iVar4 = (int)sVar3;
    *(float *)(iVar8 + 4) =
         *(float *)(iVar8 + 4) +
         (float)((double)CONCAT44(0x43300000,iVar4 >> 4 ^ 0x80000000) - DOUBLE_803e4cf8);
    if (*(float *)(iVar8 + 0x10) < FLOAT_803e4d14) {
      *(float *)(iVar8 + 0x10) = *(float *)(iVar8 + 0x10) + FLOAT_803e4d18;
    }
    iVar4 = iVar4 / 0xb6 + (iVar4 >> 0x1f);
    uVar2 = iVar4 - (iVar4 >> 0x1f);
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    fVar1 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4cf8) *
            FLOAT_803e4cd4;
    if (FLOAT_803e4cf0 < fVar1) {
      *(float *)(iVar8 + 0x10) = *(float *)(iVar8 + 0x10) / fVar1;
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) + FLOAT_803e4d1c;
    }
    if (FLOAT_803e4cd8 < *(float *)(iVar8 + 8)) {
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) / FLOAT_803e4d10;
    }
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar7 + 0x68);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar7 + 0x70);
  }
  return;
}

