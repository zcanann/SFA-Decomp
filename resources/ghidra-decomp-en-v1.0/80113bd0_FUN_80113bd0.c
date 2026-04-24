// Function: FUN_80113bd0
// Entry: 80113bd0
// Size: 396 bytes

void FUN_80113bd0(undefined4 param_1,undefined4 param_2,uint param_3,undefined2 *param_4,
                 undefined2 *param_5,undefined2 *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  short sVar5;
  short *psVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_802860d8();
  psVar6 = (short *)((ulonglong)uVar11 >> 0x20);
  iVar8 = (int)uVar11;
  iVar9 = *(int *)(psVar6 + 0x5c);
  if ((psVar6 == (short *)0x0) || (iVar8 == 0)) {
    *param_4 = 0;
    *param_5 = 0;
    *param_6 = 0;
  }
  else {
    fVar1 = *(float *)(iVar8 + 0x18) - *(float *)(psVar6 + 0xc);
    fVar2 = *(float *)(iVar8 + 0x1c) - *(float *)(psVar6 + 0xe);
    fVar3 = *(float *)(iVar8 + 0x20) - *(float *)(psVar6 + 0x10);
    uVar7 = FUN_800217c0(-(double)fVar1,-(double)fVar3);
    if (*(short **)(psVar6 + 0x18) == (short *)0x0) {
      sVar5 = *psVar6;
    }
    else {
      sVar5 = *psVar6 + **(short **)(psVar6 + 0x18);
    }
    uVar7 = (uVar7 & 0xffff) - ((int)sVar5 & 0xffffU);
    if (0x8000 < (int)uVar7) {
      uVar7 = uVar7 - 0xffff;
    }
    if ((int)uVar7 < -0x8000) {
      uVar7 = uVar7 + 0xffff;
    }
    uVar4 = uVar7 & 0xffff;
    *param_5 = (short)uVar4;
    if ((uVar4 < 0x31c4) || (0xce3b < uVar4)) {
      *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) & 0xffef;
    }
    else {
      *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) | 0x10;
    }
    *param_4 = (short)((uVar7 & 0xffff) / (0x10000 / (param_3 & 0xff)));
    dVar10 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *param_6 = (short)(int)dVar10;
  }
  FUN_80286124();
  return;
}

