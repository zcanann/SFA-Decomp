// Function: FUN_80026790
// Entry: 80026790
// Size: 408 bytes

void FUN_80026790(int param_1,undefined4 param_2,int param_3,int *param_4)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  longlong local_28;
  longlong local_20;
  
  iVar2 = *(int *)(param_1 + ((*(ushort *)(param_1 + 0x18) & 1) + 3) * 4);
  local_38 = *(undefined4 *)(iVar2 + 0x20);
  local_34 = *(undefined4 *)(iVar2 + 0x24);
  local_30 = *(undefined4 *)(iVar2 + 0x28);
  dVar6 = (double)FUN_8024782c(&local_38,&DAT_802cabb8);
  if (dVar6 < (double)FLOAT_803de828) {
    dVar6 = (double)FLOAT_803de828;
  }
  fVar1 = FLOAT_803dcb48 * (float)((double)FLOAT_803de844 - dVar6);
  iVar2 = (int)(FLOAT_803de84c * fVar1);
  local_28 = (longlong)iVar2;
  iVar5 = (int)(FLOAT_803de850 * fVar1);
  local_20 = (longlong)iVar5;
  uVar3 = FUN_800221a0(iVar2,iVar5);
  fVar1 = FLOAT_803de848 *
          (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803de820);
  iVar2 = 0;
  for (iVar5 = 0; iVar5 < param_4[2] + 1; iVar5 = iVar5 + 1) {
    iVar4 = *param_4 + iVar2;
    *(float *)(iVar4 + 0xc) =
         *(float *)(iVar4 + 0xc) * *(float *)(param_3 + 0xc) + DAT_802cabb8 * fVar1;
    *(float *)(iVar4 + 0x10) =
         DAT_802cabbc * fVar1 +
         *(float *)(iVar4 + 0x10) * *(float *)(param_3 + 0xc) + *(float *)(param_3 + 0x10);
    *(float *)(iVar4 + 0x14) =
         *(float *)(iVar4 + 0x14) * *(float *)(param_3 + 0xc) + DAT_802cabc0 * fVar1;
    iVar2 = iVar2 + 0x54;
  }
  return;
}

