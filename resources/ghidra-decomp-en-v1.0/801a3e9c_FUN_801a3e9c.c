// Function: FUN_801a3e9c
// Entry: 801a3e9c
// Size: 456 bytes

void FUN_801a3e9c(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  byte *pbVar6;
  bool bVar7;
  bool bVar8;
  double dVar9;
  
  iVar2 = FUN_802860dc();
  iVar3 = FUN_8002b9ec();
  iVar4 = FUN_8002b9ac();
  if (iVar3 == 0) {
    bVar7 = false;
  }
  else {
    dVar9 = (double)FUN_80021690(iVar2 + 0x18,iVar3 + 0x18);
    bVar7 = dVar9 < (double)FLOAT_803e43b8;
  }
  if (iVar4 == 0) {
    bVar8 = false;
  }
  else {
    dVar9 = (double)FUN_80021690(iVar2 + 0x18,iVar4 + 0x18);
    bVar8 = dVar9 < (double)FLOAT_803e43b8;
  }
  pbVar6 = *(byte **)(iVar2 + 0xb8);
  iVar2 = *(int *)(iVar2 + 0x4c);
  if (*pbVar6 >> 5 == 0) {
    iVar3 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x18));
    if (((iVar3 != 0) && ((*(short *)(iVar2 + 0x22) == -1 || (iVar3 = FUN_8001ffb4(), iVar3 != 0))))
       && ((FUN_800200e8((int)*(short *)(iVar2 + 0x1a),1), bVar7 || (bVar8)))) {
      *pbVar6 = *pbVar6 & 0x1f | 0x40;
    }
  }
  else if (((*pbVar6 >> 5 == 1) &&
           (((iVar3 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x18)), iVar3 != 0 ||
             ((*(short *)(iVar2 + 0x22) != -1 && (iVar2 = FUN_8001ffb4(), iVar2 != 0)))) && (!bVar7)
            ))) && (!bVar8)) {
    *pbVar6 = *pbVar6 & 0x1f | 0x60;
  }
  bVar1 = *pbVar6;
  if (bVar1 >> 5 == 2) {
    if (*(char *)(param_3 + 0x80) == '\x02') {
      *pbVar6 = bVar1 & 0x1f | 0x20;
    }
  }
  else if ((bVar1 >> 5 == 3) && (*(char *)(param_3 + 0x80) == '\x01')) {
    *pbVar6 = bVar1 & 0x1f;
  }
  uVar5 = 0;
  if ((*pbVar6 >> 5 != 2) && (*pbVar6 >> 5 != 3)) {
    uVar5 = 1;
  }
  FUN_80286128(uVar5);
  return;
}

