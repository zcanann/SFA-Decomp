// Function: FUN_80029834
// Entry: 80029834
// Size: 880 bytes

void FUN_80029834(undefined4 param_1,undefined4 param_2,int param_3,undefined4 *param_4,uint param_5
                 )

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  undefined8 uVar11;
  undefined2 local_48 [36];
  
  uVar11 = FUN_802860b0();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  FUN_8002a3d4(*(undefined *)(iVar5 + 6),6,*(undefined *)(iVar5 + 6),6);
  FUN_80029764();
  if (*(short *)(iVar5 + 2) != 0) {
    uVar7 = (uint)*(byte *)(*(int *)(iVar5 + 0xc) + 0x73) * 0x20 + 0x1f >> 5;
    FUN_800229f8(DAT_80340898,param_3 + *(int *)(*(int *)(iVar5 + 0xc) + 0x60),uVar7);
    local_48[0] = (undefined2)uVar7;
    FUN_800229f8(DAT_8034089c,*(undefined4 *)(*(int *)(iVar5 + 0xc) + 100),
                 (uint)*(byte *)(*(int *)(iVar5 + 0xc) + 0x6f) * 0x20 + 0x1f >> 5);
    iVar10 = 0;
    puVar9 = param_4;
    for (uVar7 = 0; uVar7 < *(ushort *)(iVar5 + 2) - 1; uVar7 = uVar7 + 1) {
      iVar8 = *(int *)(iVar5 + 0xc) + iVar10;
      uVar1 = (uint)*(byte *)(iVar8 + 0xe7) * 0x20 + 0x1f >> 5;
      uVar2 = uVar7 + 1 & 1;
      FUN_800229f8((&DAT_80340898)[uVar2 * 2],param_3 + *(int *)(iVar8 + 0xd4),uVar1);
      local_48[uVar2] = (short)uVar1;
      iVar4 = *(int *)(iVar5 + 0xc) + iVar10;
      FUN_800229f8((&DAT_80340898)[uVar2 * 2 + 1],*(undefined4 *)(iVar4 + 0xd8),
                   (uint)*(byte *)(iVar4 + 0xe3) * 0x20 + 0x1f >> 5);
      FUN_800229c4(2);
      if ((param_5 & 0xff) == 0) {
        uVar6 = *puVar9;
        uVar1 = uVar7 & 1;
        iVar4 = (uint)*(byte *)(iVar8 + 0x72) + (&DAT_80340898)[uVar1 * 2];
        FUN_80029f9c(iVar3 + (uint)*(byte *)(iVar8 + 0x6c) * 0x30,
                     iVar3 + (uint)*(byte *)(iVar8 + 0x6d) * 0x30,(&DAT_8034089c)[uVar1 * 2],iVar4,
                     iVar4,*(undefined2 *)(iVar8 + 0x70));
        FUN_80022948(uVar6,(&DAT_80340898)[uVar1 * 2],local_48[uVar7 & 1]);
      }
      else {
        uVar6 = *puVar9;
        uVar1 = uVar7 & 1;
        iVar4 = (uint)*(byte *)(iVar8 + 0x72) + (&DAT_80340898)[uVar1 * 2];
        FUN_8002a110(iVar3 + (uint)*(byte *)(iVar8 + 0x6c) * 0x30,
                     iVar3 + (uint)*(byte *)(iVar8 + 0x6d) * 0x30,(&DAT_8034089c)[uVar1 * 2],iVar4,
                     iVar4,*(undefined2 *)(iVar8 + 0x70));
        FUN_80022948(uVar6,(&DAT_80340898)[uVar1 * 2],local_48[uVar7 & 1]);
      }
      iVar10 = iVar10 + 0x74;
      puVar9 = puVar9 + 1;
    }
    iVar5 = *(int *)(iVar5 + 0xc) + uVar7 * 0x74;
    FUN_800229c4(0);
    if ((param_5 & 0xff) == 0) {
      uVar6 = param_4[uVar7];
      uVar7 = uVar7 & 1;
      iVar10 = (uint)*(byte *)(iVar5 + 0x72) + (&DAT_80340898)[uVar7 * 2];
      FUN_80029f9c(iVar3 + (uint)*(byte *)(iVar5 + 0x6c) * 0x30,
                   iVar3 + (uint)*(byte *)(iVar5 + 0x6d) * 0x30,(&DAT_8034089c)[uVar7 * 2],iVar10,
                   iVar10,*(undefined2 *)(iVar5 + 0x70));
      FUN_80022948(uVar6,(&DAT_80340898)[uVar7 * 2],local_48[uVar7]);
    }
    else {
      uVar6 = param_4[uVar7];
      uVar7 = uVar7 & 1;
      iVar10 = (uint)*(byte *)(iVar5 + 0x72) + (&DAT_80340898)[uVar7 * 2];
      FUN_8002a110(iVar3 + (uint)*(byte *)(iVar5 + 0x6c) * 0x30,
                   iVar3 + (uint)*(byte *)(iVar5 + 0x6d) * 0x30,(&DAT_8034089c)[uVar7 * 2],iVar10,
                   iVar10,*(undefined2 *)(iVar5 + 0x70));
      FUN_80022948(uVar6,(&DAT_80340898)[uVar7 * 2],local_48[uVar7]);
    }
    FUN_800229c4(0);
  }
  FUN_802860fc();
  return;
}

