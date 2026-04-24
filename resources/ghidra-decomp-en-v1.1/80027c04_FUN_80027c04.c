// Function: FUN_80027c04
// Entry: 80027c04
// Size: 704 bytes

void FUN_80027c04(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,int param_5)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  float *pfVar9;
  int iVar10;
  int iVar11;
  undefined8 uVar12;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  
  uVar12 = FUN_8028682c();
  piVar3 = (int *)((ulonglong)uVar12 >> 0x20);
  iVar4 = (int)uVar12;
  uVar8 = 0;
  iVar5 = *(int *)(param_5 + 0x54);
  if (iVar5 != 0) {
    if (*(char *)(*(int *)(param_5 + 0x50) + 0x66) == '\0') {
      uVar8 = *(undefined4 *)(iVar5 + 0x48);
    }
    else {
      uVar7 = (int)*(short *)(iVar5 + 4) >> 2;
      if (0 < (int)uVar7) {
        uStack_34 = uVar7 ^ 0x80000000;
        local_38 = 0x43300000;
        iVar1 = (int)(*(float *)(param_5 + 0x98) *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df4a0));
        local_30 = (longlong)iVar1;
        if ((int)uVar7 <= iVar1) {
          iVar1 = uVar7 - 1;
        }
        uVar8 = *(undefined4 *)(*(int *)(iVar5 + 8) + iVar1 * 4);
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
    *(undefined4 *)(*(int *)(param_3 + 0x54) + 0x48) = uVar8;
  }
  *(ushort *)(piVar3 + 6) = *(ushort *)(piVar3 + 6) ^ 4;
  uVar7 = *(ushort *)(piVar3 + 6) >> 2 & 1;
  piVar3[0x14] = piVar3[uVar7 + 0x12];
  iVar11 = 0;
  iVar10 = 0;
  iVar1 = piVar3[(uVar7 ^ 1) + 0x12];
  pfVar9 = param_4;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar4 + 0xf7); iVar5 = iVar5 + 1) {
    if (param_4 == (float *)0x0) {
      iVar6 = (int)*(short *)(*(int *)(iVar4 + 0x58) + iVar11);
      uVar7 = (uint)*(byte *)(*piVar3 + 0xf3);
      if (uVar7 == 0) {
        iVar2 = 1;
      }
      else {
        iVar2 = uVar7 + *(byte *)(*piVar3 + 0xf4);
      }
      if (iVar2 <= iVar6) {
        iVar6 = 0;
      }
      pfVar9 = (float *)(piVar3[(*(ushort *)(piVar3 + 6) & 1) + 3] + iVar6 * 0x40);
    }
    if ((iVar5 == 0) && (param_5 != param_3)) {
      local_48 = FLOAT_803df4a8;
      local_44 = FLOAT_803df4a8;
      local_40 = FLOAT_803df4a8;
      FUN_80247bf8(pfVar9,&local_48,&local_48);
      *(float *)(param_3 + 0xc) = local_48 + FLOAT_803dda58;
      *(float *)(param_3 + 0x10) = local_44;
      *(float *)(param_3 + 0x14) = local_40 + FLOAT_803dda5c;
      FUN_8000e12c(param_3,(float *)(param_3 + 0x18),(float *)(param_3 + 0x1c),
                   (float *)(param_3 + 0x20));
    }
    iVar6 = *(int *)(iVar4 + 0x58);
    local_48 = *(float *)(iVar6 + iVar11 + 8);
    local_44 = *(float *)(iVar6 + iVar11 + 0xc);
    local_40 = *(float *)(iVar6 + iVar11 + 0x10);
    *(float *)(piVar3[0x14] + iVar10) = *(float *)(iVar6 + iVar11 + 4) * *(float *)(param_5 + 8);
    FUN_80247bf8(pfVar9,&local_48,(float *)(piVar3[0x14] + iVar10 + 4));
    *(float *)(iVar1 + 4) = (FLOAT_803ddb50 + *(float *)(iVar1 + 4)) - FLOAT_803dda58;
    *(float *)(iVar1 + 0xc) = (FLOAT_803ddb4c + *(float *)(iVar1 + 0xc)) - FLOAT_803dda5c;
    iVar11 = iVar11 + 0x18;
    iVar10 = iVar10 + 0x10;
    iVar1 = iVar1 + 0x10;
  }
  FUN_80286878();
  return;
}

