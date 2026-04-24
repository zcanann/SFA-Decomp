// Function: FUN_8002a444
// Entry: 8002a444
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x8002a4fc) */

void FUN_8002a444(undefined4 param_1,undefined4 param_2,ushort *param_3,int param_4)

{
  byte bVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  ushort *puVar8;
  undefined8 uVar9;
  undefined auStack72 [20];
  undefined auStack52 [52];
  
  uVar9 = FUN_802860d4();
  iVar5 = (int)((ulonglong)uVar9 >> 0x20);
  FUN_80003494(param_3,iVar5,*(undefined2 *)(iVar5 + 2));
  uVar6 = (uint)param_3[1];
  iVar7 = iVar5 + uVar6;
  bVar1 = *(byte *)(param_3 + 4);
  iVar4 = (param_4 - uVar6) * 8;
  FUN_80013a64(auStack52,(int)param_3 + uVar6,iVar4,iVar4);
  iVar4 = ((int)uVar9 - (uint)param_3[1]) * 8;
  FUN_80013a64(auStack72,iVar7,iVar4,iVar4);
  FUN_800033a8((int)param_3 + uVar6,0,param_4 - (uint)param_3[1]);
  puVar8 = param_3 + 5;
  uVar3 = param_3[1];
  while (puVar8 < (ushort *)((int)param_3 + (uint)uVar3)) {
    uVar2 = *puVar8;
    puVar8 = puVar8 + 1;
    if ((uVar2 & 0xf) != 0) {
      iVar7 = FUN_80006744(iVar7,*(undefined *)((int)param_3 + 7),auStack52,(uint)bVar1 << 3);
    }
  }
  *param_3 = *param_3 & 0xffdf;
  uVar3 = param_3[2];
  if (uVar3 != 0) {
    param_3[2] = param_3[1] +
                 (short)((int)((uint)bVar1 << 3) >> 3) * (*(byte *)((int)param_3 + 7) + 2);
    param_3[2] = param_3[2] + 7 & 0xfff8;
    FUN_80003494((int)param_3 + (uint)param_3[2],iVar5 + (uint)*(ushort *)(iVar5 + 4),
                 (int)uVar9 - (uint)uVar3);
  }
  FUN_80286120();
  return;
}

