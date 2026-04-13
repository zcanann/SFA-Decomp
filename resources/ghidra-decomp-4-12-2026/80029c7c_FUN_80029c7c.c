// Function: FUN_80029c7c
// Entry: 80029c7c
// Size: 628 bytes

void FUN_80029c7c(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,int param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  float *pfVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  uint uVar10;
  undefined8 uVar11;
  ushort local_48 [36];
  
  uVar11 = FUN_8028681c();
  iVar4 = (int)((ulonglong)uVar11 >> 0x20);
  iVar3 = (int)uVar11;
  FUN_8002a4ac();
  FUN_8002983c();
  if (*(short *)(iVar3 + 2) != 0) {
    uVar10 = (uint)*(byte *)(*(int *)(iVar3 + 0xc) + 0x73) * 0x20 + 0x1f >> 5;
    FUN_80022abc(DAT_803414f8,param_3 + *(int *)(*(int *)(iVar3 + 0xc) + 0x60),uVar10);
    local_48[0] = (ushort)uVar10;
    FUN_80022abc(DAT_803414fc,*(uint *)(*(int *)(iVar3 + 0xc) + 100),
                 (uint)*(byte *)(*(int *)(iVar3 + 0xc) + 0x6f) * 0x20 + 0x1f >> 5);
    iVar9 = 0;
    piVar8 = param_4;
    for (uVar10 = 0; uVar10 < *(ushort *)(iVar3 + 2) - 1; uVar10 = uVar10 + 1) {
      iVar7 = *(int *)(iVar3 + 0xc) + iVar9;
      uVar1 = (uint)*(byte *)(iVar7 + 0xe7) * 0x20 + 0x1f >> 5;
      uVar2 = uVar10 + 1 & 1;
      FUN_80022abc((&DAT_803414f8)[uVar2 * 2],param_3 + *(int *)(iVar7 + 0xd4),uVar1);
      local_48[uVar2] = (ushort)uVar1;
      iVar5 = *(int *)(iVar3 + 0xc) + iVar9;
      FUN_80022abc((&DAT_803414f8)[uVar2 * 2 + 1],*(uint *)(iVar5 + 0xd8),
                   (uint)*(byte *)(iVar5 + 0xe3) * 0x20 + 0x1f >> 5);
      FUN_80022a88(2);
      iVar5 = *piVar8;
      uVar1 = uVar10 & 1;
      pfVar6 = (float *)((uint)*(byte *)(iVar7 + 0x72) + (&DAT_803414f8)[uVar1 * 2]);
      FUN_80029ef0((float *)(iVar4 + (uint)*(byte *)(iVar7 + 0x6c) * 0x30),
                   (float *)(iVar4 + (uint)*(byte *)(iVar7 + 0x6d) * 0x30),
                   (float *)(&DAT_803414fc)[uVar1 * 2],pfVar6,(int)pfVar6,
                   (uint)*(ushort *)(iVar7 + 0x70));
      FUN_80022a0c(param_5 + iVar5,(&DAT_803414f8)[uVar1 * 2],(uint)local_48[uVar10 & 1]);
      iVar9 = iVar9 + 0x74;
      piVar8 = piVar8 + 1;
    }
    iVar9 = *(int *)(iVar3 + 0xc) + uVar10 * 0x74;
    FUN_80022a88(0);
    iVar3 = param_4[uVar10];
    uVar10 = uVar10 & 1;
    pfVar6 = (float *)((uint)*(byte *)(iVar9 + 0x72) + (&DAT_803414f8)[uVar10 * 2]);
    FUN_80029ef0((float *)(iVar4 + (uint)*(byte *)(iVar9 + 0x6c) * 0x30),
                 (float *)(iVar4 + (uint)*(byte *)(iVar9 + 0x6d) * 0x30),
                 (float *)(&DAT_803414fc)[uVar10 * 2],pfVar6,(int)pfVar6,
                 (uint)*(ushort *)(iVar9 + 0x70));
    FUN_80022a0c(param_5 + iVar3,(&DAT_803414f8)[uVar10 * 2],(uint)local_48[uVar10]);
    FUN_80022a88(0);
  }
  FUN_80286868();
  return;
}

