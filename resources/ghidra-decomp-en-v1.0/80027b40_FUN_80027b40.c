// Function: FUN_80027b40
// Entry: 80027b40
// Size: 704 bytes

void FUN_80027b40(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  
  uVar11 = FUN_802860c8();
  piVar3 = (int *)((ulonglong)uVar11 >> 0x20);
  iVar4 = (int)uVar11;
  uVar7 = 0;
  iVar5 = *(int *)(param_5 + 0x54);
  if (iVar5 != 0) {
    if (*(char *)(*(int *)(param_5 + 0x50) + 0x66) == '\0') {
      uVar7 = *(undefined4 *)(iVar5 + 0x48);
    }
    else {
      uVar6 = (int)*(short *)(iVar5 + 4) >> 2;
      if (0 < (int)uVar6) {
        uStack52 = uVar6 ^ 0x80000000;
        local_38 = 0x43300000;
        iVar1 = (int)(*(float *)(param_5 + 0x98) *
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de820));
        local_30 = (longlong)iVar1;
        if ((int)uVar6 <= iVar1) {
          iVar1 = uVar6 - 1;
        }
        uVar7 = *(undefined4 *)(*(int *)(iVar5 + 8) + iVar1 * 4);
      }
    }
  }
  iVar5 = *(int *)(param_3 + 0x54);
  if (iVar5 != 0) {
    *(char *)(iVar5 + 0xaf) = *(char *)(iVar5 + 0xaf) + -1;
    if (*(char *)(*(int *)(param_3 + 0x54) + 0xaf) < '\0') {
      *(undefined *)(*(int *)(param_3 + 0x54) + 0xaf) = 0;
    }
    *(undefined4 *)(*(int *)(param_3 + 0x54) + 0x4c) =
         *(undefined4 *)(*(int *)(param_3 + 0x54) + 0x48);
    *(undefined4 *)(*(int *)(param_3 + 0x54) + 0x48) = uVar7;
  }
  *(ushort *)(piVar3 + 6) = *(ushort *)(piVar3 + 6) ^ 4;
  uVar6 = *(ushort *)(piVar3 + 6) >> 2 & 1;
  piVar3[0x14] = piVar3[uVar6 + 0x12];
  iVar10 = 0;
  iVar9 = 0;
  iVar8 = piVar3[(uVar6 ^ 1) + 0x12];
  iVar5 = param_4;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(iVar4 + 0xf7); iVar1 = iVar1 + 1) {
    if (param_4 == 0) {
      iVar5 = (int)*(short *)(*(int *)(iVar4 + 0x58) + iVar10);
      uVar6 = (uint)*(byte *)(*piVar3 + 0xf3);
      if (uVar6 == 0) {
        iVar2 = 1;
      }
      else {
        iVar2 = uVar6 + *(byte *)(*piVar3 + 0xf4);
      }
      if (iVar2 <= iVar5) {
        iVar5 = 0;
      }
      iVar5 = piVar3[(*(ushort *)(piVar3 + 6) & 1) + 3] + iVar5 * 0x40;
    }
    if ((iVar1 == 0) && (param_5 != param_3)) {
      local_48 = FLOAT_803de828;
      local_44 = FLOAT_803de828;
      local_40 = FLOAT_803de828;
      FUN_80247494(iVar5,&local_48,&local_48);
      *(float *)(param_3 + 0xc) = local_48 + FLOAT_803dcdd8;
      *(float *)(param_3 + 0x10) = local_44;
      *(float *)(param_3 + 0x14) = local_40 + FLOAT_803dcddc;
      FUN_8000e10c(param_3,param_3 + 0x18,param_3 + 0x1c,param_3 + 0x20);
    }
    iVar2 = *(int *)(iVar4 + 0x58);
    local_48 = *(float *)(iVar2 + iVar10 + 8);
    local_44 = *(float *)(iVar2 + iVar10 + 0xc);
    local_40 = *(float *)(iVar2 + iVar10 + 0x10);
    *(float *)(piVar3[0x14] + iVar9) = *(float *)(iVar2 + iVar10 + 4) * *(float *)(param_5 + 8);
    FUN_80247494(iVar5,&local_48,piVar3[0x14] + iVar9 + 4);
    *(float *)(iVar8 + 4) = (FLOAT_803dced0 + *(float *)(iVar8 + 4)) - FLOAT_803dcdd8;
    *(float *)(iVar8 + 0xc) = (FLOAT_803dcecc + *(float *)(iVar8 + 0xc)) - FLOAT_803dcddc;
    iVar10 = iVar10 + 0x18;
    iVar9 = iVar9 + 0x10;
    iVar8 = iVar8 + 0x10;
  }
  FUN_80286114();
  return;
}

