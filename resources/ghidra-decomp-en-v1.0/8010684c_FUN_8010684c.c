// Function: FUN_8010684c
// Entry: 8010684c
// Size: 1336 bytes

void FUN_8010684c(undefined4 param_1,undefined4 param_2,short param_3,short param_4,
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
  undefined8 uVar9;
  
  uVar9 = FUN_802860cc();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  puVar3 = (ushort *)uVar9;
  sVar5 = (short)param_5;
  if (param_4 < sVar5) {
    uVar1 = *puVar3;
    *puVar3 = uVar1 + 1;
    *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
  }
  else {
    sVar8 = param_4 >> 1;
    sVar7 = param_4 >> 2;
    sVar6 = param_4 >> 3;
    param_4 = param_4 >> 4;
    if (sVar8 < sVar5) {
      uVar1 = *puVar3;
      *puVar3 = uVar1 + 1;
      *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
    }
    else {
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar6;
      }
      else {
        FUN_8010684c();
        FUN_8010684c(iVar2,puVar3,(int)(short)(param_3 + param_4),(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(param_3 + sVar6),(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(param_3 + sVar6 + param_4),(int)param_4,param_5);
      }
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar7;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar7;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar7 + sVar6;
      }
      else {
        FUN_8010684c(iVar2,puVar3,(int)(short)(param_3 + sVar7),(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(param_3 + sVar7 + param_4),(int)param_4,param_5);
        sVar4 = param_3 + sVar7 + sVar6;
        FUN_8010684c(iVar2,puVar3,(int)sVar4,(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(sVar4 + param_4),(int)param_4,param_5);
      }
    }
    if (sVar8 < sVar5) {
      uVar1 = *puVar3;
      *puVar3 = uVar1 + 1;
      *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
    }
    else {
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar6;
      }
      else {
        FUN_8010684c(iVar2,puVar3,(int)(short)(param_3 + sVar8),(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(param_3 + sVar8 + param_4),(int)param_4,param_5);
        sVar4 = param_3 + sVar8 + sVar6;
        FUN_8010684c(iVar2,puVar3,(int)sVar4,(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(sVar4 + param_4),(int)param_4,param_5);
      }
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar7;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar7;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar7 + sVar6;
      }
      else {
        sVar5 = param_3 + sVar8 + sVar7;
        FUN_8010684c(iVar2,puVar3,(int)sVar5,(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(sVar5 + param_4),(int)param_4,param_5);
        sVar6 = param_3 + sVar8 + sVar7 + sVar6;
        FUN_8010684c(iVar2,puVar3,(int)sVar6,(int)param_4,param_5);
        FUN_8010684c(iVar2,puVar3,(int)(short)(sVar6 + param_4),(int)param_4,param_5);
      }
    }
  }
  FUN_80286118();
  return;
}

