// Function: FUN_80113e6c
// Entry: 80113e6c
// Size: 396 bytes

void FUN_80113e6c(undefined4 param_1,undefined4 param_2,uint param_3,undefined2 *param_4,
                 undefined2 *param_5,undefined2 *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  ushort uVar4;
  ushort *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_8028683c();
  puVar5 = (ushort *)((ulonglong)uVar10 >> 0x20);
  iVar7 = (int)uVar10;
  iVar8 = *(int *)(puVar5 + 0x5c);
  if ((puVar5 == (ushort *)0x0) || (iVar7 == 0)) {
    *param_4 = 0;
    *param_5 = 0;
    *param_6 = 0;
  }
  else {
    fVar1 = *(float *)(iVar7 + 0x18) - *(float *)(puVar5 + 0xc);
    fVar2 = *(float *)(iVar7 + 0x1c) - *(float *)(puVar5 + 0xe);
    fVar3 = *(float *)(iVar7 + 0x20) - *(float *)(puVar5 + 0x10);
    uVar6 = FUN_80021884();
    if (*(short **)(puVar5 + 0x18) == (short *)0x0) {
      uVar4 = *puVar5;
    }
    else {
      uVar4 = *puVar5 + **(short **)(puVar5 + 0x18);
    }
    uVar6 = (uVar6 & 0xffff) - (uint)uVar4;
    if (0x8000 < (int)uVar6) {
      uVar6 = uVar6 - 0xffff;
    }
    if ((int)uVar6 < -0x8000) {
      uVar6 = uVar6 + 0xffff;
    }
    *param_5 = (short)uVar6;
    if (((uVar6 & 0xffff) < 0x31c4) || (0xce3b < (uVar6 & 0xffff))) {
      *(ushort *)(iVar8 + 0x400) = *(ushort *)(iVar8 + 0x400) & 0xffef;
    }
    else {
      *(ushort *)(iVar8 + 0x400) = *(ushort *)(iVar8 + 0x400) | 0x10;
    }
    *param_4 = (short)((uVar6 & 0xffff) / (0x10000 / (param_3 & 0xff)));
    dVar9 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *param_6 = (short)(int)dVar9;
  }
  FUN_80286888();
  return;
}

