// Function: FUN_80026854
// Entry: 80026854
// Size: 408 bytes

void FUN_80026854(int param_1,undefined4 param_2,int param_3,int *param_4)

{
  uint uVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  longlong local_28;
  longlong local_20;
  
  iVar3 = *(int *)(param_1 + (*(ushort *)(param_1 + 0x18) & 1) * 4 + 0xc);
  local_38 = *(float *)(iVar3 + 0x20);
  local_34 = *(undefined4 *)(iVar3 + 0x24);
  local_30 = *(undefined4 *)(iVar3 + 0x28);
  dVar7 = FUN_80247f90(&local_38,&DAT_802cb778);
  if (dVar7 < (double)FLOAT_803df4a8) {
    dVar7 = (double)FLOAT_803df4a8;
  }
  fVar2 = FLOAT_803dd7c8 * (float)((double)FLOAT_803df4c4 - dVar7);
  uVar4 = (uint)(FLOAT_803df4cc * fVar2);
  local_28 = (longlong)(int)uVar4;
  uVar1 = (uint)(FLOAT_803df4d0 * fVar2);
  local_20 = (longlong)(int)uVar1;
  uVar4 = FUN_80022264(uVar4,uVar1);
  fVar2 = FLOAT_803df4c8 *
          (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803df4a0);
  iVar3 = 0;
  for (iVar6 = 0; iVar6 < param_4[2] + 1; iVar6 = iVar6 + 1) {
    iVar5 = *param_4 + iVar3;
    *(float *)(iVar5 + 0xc) =
         *(float *)(iVar5 + 0xc) * *(float *)(param_3 + 0xc) + DAT_802cb778 * fVar2;
    *(float *)(iVar5 + 0x10) =
         DAT_802cb77c * fVar2 +
         *(float *)(iVar5 + 0x10) * *(float *)(param_3 + 0xc) + *(float *)(param_3 + 0x10);
    *(float *)(iVar5 + 0x14) =
         *(float *)(iVar5 + 0x14) * *(float *)(param_3 + 0xc) + DAT_802cb780 * fVar2;
    iVar3 = iVar3 + 0x54;
  }
  return;
}

