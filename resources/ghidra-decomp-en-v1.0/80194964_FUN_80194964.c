// Function: FUN_80194964
// Entry: 80194964
// Size: 504 bytes

void FUN_80194964(undefined4 param_1,undefined4 param_2,int param_3)

{
  ushort uVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  undefined2 *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860cc();
  iVar4 = (int)uVar10;
  iVar9 = 0;
  iVar8 = 0;
  for (iVar7 = 0; iVar7 < (int)(uint)*(ushort *)(param_3 + 0x9a); iVar7 = iVar7 + 1) {
    puVar2 = (ushort *)FUN_800606ec(param_3,iVar7);
    iVar3 = FUN_80060678();
    if (*(char *)((int)((ulonglong)uVar10 >> 0x20) + 0x28) == iVar3) {
      *(ushort *)(*(int *)(iVar4 + 0x10) + iVar9) = puVar2[3];
      *(ushort *)(*(int *)(iVar4 + 0x14) + iVar9) = puVar2[4];
      iVar9 = iVar9 + 2;
      uVar1 = puVar2[10];
      iVar3 = iVar8;
      for (uVar6 = (uint)*puVar2; (int)uVar6 < (int)(uint)uVar1; uVar6 = uVar6 + 1) {
        puVar2 = (ushort *)FUN_800606dc(param_3,uVar6);
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)*puVar2 * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 2) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 4) = puVar5[2];
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)puVar2[1] * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 6) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 8) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 10) = puVar5[2];
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)puVar2[2] * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 0xc) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 0xe) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar3 + 0x10) = puVar5[2];
        iVar3 = iVar3 + 0x12;
        iVar8 = iVar8 + 0x12;
      }
    }
  }
  iVar7 = 0;
  for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(param_3 + 0xa1); iVar8 = iVar8 + 1) {
    iVar9 = FUN_800606fc(param_3,iVar8);
    *(undefined2 *)(*(int *)(iVar4 + 0x28) + iVar7) = *(undefined2 *)(iVar9 + 6);
    *(undefined2 *)(*(int *)(iVar4 + 0x2c) + iVar7) = *(undefined2 *)(iVar9 + 0xc);
    *(undefined2 *)(*(int *)(iVar4 + 0x30) + iVar7) = *(undefined2 *)(iVar9 + 8);
    *(undefined2 *)(*(int *)(iVar4 + 0x34) + iVar7) = *(undefined2 *)(iVar9 + 0xe);
    *(undefined2 *)(*(int *)(iVar4 + 0x38) + iVar7) = *(undefined2 *)(iVar9 + 10);
    *(undefined2 *)(*(int *)(iVar4 + 0x3c) + iVar7) = *(undefined2 *)(iVar9 + 0x10);
    iVar7 = iVar7 + 2;
  }
  FUN_80286118();
  return;
}

