// Function: FUN_80029ba4
// Entry: 80029ba4
// Size: 628 bytes

void FUN_80029ba4(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,int param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  uint uVar10;
  undefined8 uVar11;
  undefined2 local_48 [36];
  
  uVar11 = FUN_802860b8();
  iVar4 = (int)((ulonglong)uVar11 >> 0x20);
  iVar3 = (int)uVar11;
  FUN_8002a3d4(*(undefined *)(iVar3 + 6),7,*(undefined *)(iVar3 + 6),7);
  FUN_80029764();
  if (*(short *)(iVar3 + 2) != 0) {
    uVar10 = (uint)*(byte *)(*(int *)(iVar3 + 0xc) + 0x73) * 0x20 + 0x1f >> 5;
    FUN_800229f8(DAT_80340898,param_3 + *(int *)(*(int *)(iVar3 + 0xc) + 0x60),uVar10);
    local_48[0] = (undefined2)uVar10;
    FUN_800229f8(DAT_8034089c,*(undefined4 *)(*(int *)(iVar3 + 0xc) + 100),
                 (uint)*(byte *)(*(int *)(iVar3 + 0xc) + 0x6f) * 0x20 + 0x1f >> 5);
    iVar9 = 0;
    piVar8 = param_4;
    for (uVar10 = 0; uVar10 < *(ushort *)(iVar3 + 2) - 1; uVar10 = uVar10 + 1) {
      iVar7 = *(int *)(iVar3 + 0xc) + iVar9;
      uVar1 = (uint)*(byte *)(iVar7 + 0xe7) * 0x20 + 0x1f >> 5;
      uVar2 = uVar10 + 1 & 1;
      FUN_800229f8((&DAT_80340898)[uVar2 * 2],param_3 + *(int *)(iVar7 + 0xd4),uVar1);
      local_48[uVar2] = (short)uVar1;
      iVar6 = *(int *)(iVar3 + 0xc) + iVar9;
      FUN_800229f8((&DAT_80340898)[uVar2 * 2 + 1],*(undefined4 *)(iVar6 + 0xd8),
                   (uint)*(byte *)(iVar6 + 0xe3) * 0x20 + 0x1f >> 5);
      FUN_800229c4(2);
      iVar6 = *piVar8;
      uVar1 = uVar10 & 1;
      iVar5 = (uint)*(byte *)(iVar7 + 0x72) + (&DAT_80340898)[uVar1 * 2];
      FUN_80029e18(iVar4 + (uint)*(byte *)(iVar7 + 0x6c) * 0x30,
                   iVar4 + (uint)*(byte *)(iVar7 + 0x6d) * 0x30,(&DAT_8034089c)[uVar1 * 2],iVar5,
                   iVar5,*(undefined2 *)(iVar7 + 0x70));
      FUN_80022948(param_5 + iVar6,(&DAT_80340898)[uVar1 * 2],local_48[uVar10 & 1]);
      iVar9 = iVar9 + 0x74;
      piVar8 = piVar8 + 1;
    }
    iVar6 = *(int *)(iVar3 + 0xc) + uVar10 * 0x74;
    FUN_800229c4(0);
    iVar3 = param_4[uVar10];
    uVar10 = uVar10 & 1;
    iVar9 = (uint)*(byte *)(iVar6 + 0x72) + (&DAT_80340898)[uVar10 * 2];
    FUN_80029e18(iVar4 + (uint)*(byte *)(iVar6 + 0x6c) * 0x30,
                 iVar4 + (uint)*(byte *)(iVar6 + 0x6d) * 0x30,(&DAT_8034089c)[uVar10 * 2],iVar9,
                 iVar9,*(undefined2 *)(iVar6 + 0x70));
    FUN_80022948(param_5 + iVar3,(&DAT_80340898)[uVar10 * 2],local_48[uVar10]);
    FUN_800229c4(0);
  }
  FUN_80286104();
  return;
}

