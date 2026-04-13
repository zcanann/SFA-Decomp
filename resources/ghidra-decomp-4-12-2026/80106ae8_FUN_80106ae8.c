// Function: FUN_80106ae8
// Entry: 80106ae8
// Size: 1336 bytes

void FUN_80106ae8(undefined4 param_1,undefined4 param_2,short param_3,short param_4,
                 undefined4 param_5)

{
  ushort uVar1;
  int iVar2;
  ushort *puVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  short sVar8;
  short sVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  iVar2 = (int)((ulonglong)uVar10 >> 0x20);
  puVar3 = (ushort *)uVar10;
  sVar6 = (short)param_5;
  if (param_4 < sVar6) {
    uVar1 = *puVar3;
    *puVar3 = uVar1 + 1;
    *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
  }
  else {
    sVar9 = param_4 >> 1;
    sVar8 = param_4 >> 2;
    sVar7 = param_4 >> 3;
    sVar4 = param_4 >> 4;
    if (sVar9 < sVar6) {
      uVar1 = *puVar3;
      *puVar3 = uVar1 + 1;
      *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
    }
    else {
      if (sVar8 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
      }
      else if (sVar7 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar7;
      }
      else {
        FUN_80106ae8(iVar2,puVar3,param_3,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,param_3 + sVar4,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,param_3 + sVar7,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,param_3 + sVar7 + sVar4,sVar4,param_5);
      }
      if (sVar8 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
      }
      else if (sVar7 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar7;
      }
      else {
        FUN_80106ae8(iVar2,puVar3,param_3 + sVar8,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,param_3 + sVar8 + sVar4,sVar4,param_5);
        sVar5 = param_3 + sVar8 + sVar7;
        FUN_80106ae8(iVar2,puVar3,sVar5,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,sVar5 + sVar4,sVar4,param_5);
      }
    }
    if (sVar9 < sVar6) {
      uVar1 = *puVar3;
      *puVar3 = uVar1 + 1;
      *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar9;
    }
    else {
      if (sVar8 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar9;
      }
      else if (sVar7 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar9;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar9 + sVar7;
      }
      else {
        FUN_80106ae8(iVar2,puVar3,param_3 + sVar9,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,param_3 + sVar9 + sVar4,sVar4,param_5);
        sVar5 = param_3 + sVar9 + sVar7;
        FUN_80106ae8(iVar2,puVar3,sVar5,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,sVar5 + sVar4,sVar4,param_5);
      }
      if (sVar8 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar9 + sVar8;
      }
      else if (sVar7 < sVar6) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar9 + sVar8;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar9 + sVar8 + sVar7;
      }
      else {
        sVar6 = param_3 + sVar9 + sVar8;
        FUN_80106ae8(iVar2,puVar3,sVar6,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,sVar6 + sVar4,sVar4,param_5);
        sVar7 = param_3 + sVar9 + sVar8 + sVar7;
        FUN_80106ae8(iVar2,puVar3,sVar7,sVar4,param_5);
        FUN_80106ae8(iVar2,puVar3,sVar7 + sVar4,sVar4,param_5);
      }
    }
  }
  FUN_8028687c();
  return;
}

