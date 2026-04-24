// Function: FUN_8002a51c
// Entry: 8002a51c
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x8002a5d4) */

void FUN_8002a51c(undefined4 param_1,undefined4 param_2,ushort *param_3,int param_4)

{
  byte bVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  ushort *puVar8;
  undefined8 uVar9;
  undefined4 auStack_48 [5];
  int aiStack_34 [13];
  
  uVar9 = FUN_80286838();
  uVar5 = (uint)((ulonglong)uVar9 >> 0x20);
  FUN_80003494((uint)param_3,uVar5,(uint)*(ushort *)(uVar5 + 2));
  uVar6 = (uint)param_3[1];
  iVar7 = uVar5 + uVar6;
  bVar1 = *(byte *)(param_3 + 4);
  uVar4 = (param_4 - uVar6) * 8;
  FUN_80013a84(aiStack_34,(int)param_3 + uVar6,uVar4,uVar4);
  uVar4 = ((int)uVar9 - (uint)param_3[1]) * 8;
  FUN_80013a84(auStack_48,iVar7,uVar4,uVar4);
  FUN_800033a8((int)param_3 + uVar6,0,param_4 - (uint)param_3[1]);
  puVar8 = param_3 + 5;
  uVar3 = param_3[1];
  while (puVar8 < (ushort *)((int)param_3 + (uint)uVar3)) {
    uVar2 = *puVar8;
    puVar8 = puVar8 + 1;
    if (((int)(short)uVar2 & 0xfU) != 0) {
      iVar7 = FUN_80006744(iVar7,(uint)*(byte *)((int)param_3 + 7),aiStack_34,(uint)bVar1 << 3,
                           (int)(short)uVar2 & 0xfU);
    }
  }
  *param_3 = *param_3 & 0xffdf;
  uVar3 = param_3[2];
  if (uVar3 != 0) {
    param_3[2] = param_3[1] +
                 (short)((int)((uint)bVar1 << 3) >> 3) * (*(byte *)((int)param_3 + 7) + 2);
    param_3[2] = param_3[2] + 7 & 0xfff8;
    FUN_80003494((int)param_3 + (uint)param_3[2],uVar5 + *(ushort *)(uVar5 + 4),
                 (int)uVar9 - (uint)uVar3);
  }
  FUN_80286884();
  return;
}

