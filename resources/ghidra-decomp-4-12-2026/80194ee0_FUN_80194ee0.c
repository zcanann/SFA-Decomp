// Function: FUN_80194ee0
// Entry: 80194ee0
// Size: 504 bytes

void FUN_80194ee0(undefined4 param_1,undefined4 param_2,int param_3)

{
  ushort uVar1;
  ushort *puVar2;
  uint uVar3;
  int iVar4;
  undefined2 *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  iVar4 = (int)uVar10;
  iVar8 = 0;
  iVar7 = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(ushort *)(param_3 + 0x9a); iVar6 = iVar6 + 1) {
    puVar2 = (ushort *)FUN_80060868(param_3,iVar6);
    uVar3 = FUN_800607f4((int)puVar2);
    if ((int)*(char *)((int)((ulonglong)uVar10 >> 0x20) + 0x28) == uVar3) {
      *(ushort *)(*(int *)(iVar4 + 0x10) + iVar8) = puVar2[3];
      *(ushort *)(*(int *)(iVar4 + 0x14) + iVar8) = puVar2[4];
      iVar8 = iVar8 + 2;
      uVar1 = puVar2[10];
      iVar9 = iVar7;
      for (uVar3 = (uint)*puVar2; (int)uVar3 < (int)(uint)uVar1; uVar3 = uVar3 + 1) {
        puVar2 = (ushort *)FUN_80060858(param_3,uVar3);
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)*puVar2 * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 2) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 4) = puVar5[2];
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)puVar2[1] * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 6) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 8) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 10) = puVar5[2];
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)puVar2[2] * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 0xc) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 0xe) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 0x10) = puVar5[2];
        iVar9 = iVar9 + 0x12;
        iVar7 = iVar7 + 0x12;
      }
    }
  }
  iVar6 = 0;
  for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_3 + 0xa1); iVar7 = iVar7 + 1) {
    iVar8 = FUN_80060878(param_3,iVar7);
    *(undefined2 *)(*(int *)(iVar4 + 0x28) + iVar6) = *(undefined2 *)(iVar8 + 6);
    *(undefined2 *)(*(int *)(iVar4 + 0x2c) + iVar6) = *(undefined2 *)(iVar8 + 0xc);
    *(undefined2 *)(*(int *)(iVar4 + 0x30) + iVar6) = *(undefined2 *)(iVar8 + 8);
    *(undefined2 *)(*(int *)(iVar4 + 0x34) + iVar6) = *(undefined2 *)(iVar8 + 0xe);
    *(undefined2 *)(*(int *)(iVar4 + 0x38) + iVar6) = *(undefined2 *)(iVar8 + 10);
    *(undefined2 *)(*(int *)(iVar4 + 0x3c) + iVar6) = *(undefined2 *)(iVar8 + 0x10);
    iVar6 = iVar6 + 2;
  }
  FUN_8028687c();
  return;
}

