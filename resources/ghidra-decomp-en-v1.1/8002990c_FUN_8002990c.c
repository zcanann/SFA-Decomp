// Function: FUN_8002990c
// Entry: 8002990c
// Size: 880 bytes

void FUN_8002990c(undefined4 param_1,undefined4 param_2,int param_3,uint *param_4,uint param_5)

{
  int iVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  undefined8 uVar11;
  ushort local_48 [36];
  
  uVar11 = FUN_80286814();
  iVar1 = (int)((ulonglong)uVar11 >> 0x20);
  iVar4 = (int)uVar11;
  FUN_8002a4ac();
  FUN_8002983c();
  if (*(short *)(iVar4 + 2) != 0) {
    uVar7 = (uint)*(byte *)(*(int *)(iVar4 + 0xc) + 0x73) * 0x20 + 0x1f >> 5;
    FUN_80022abc(DAT_803414f8,param_3 + *(int *)(*(int *)(iVar4 + 0xc) + 0x60),uVar7);
    local_48[0] = (ushort)uVar7;
    FUN_80022abc(DAT_803414fc,*(uint *)(*(int *)(iVar4 + 0xc) + 100),
                 (uint)*(byte *)(*(int *)(iVar4 + 0xc) + 0x6f) * 0x20 + 0x1f >> 5);
    iVar10 = 0;
    puVar9 = param_4;
    for (uVar7 = 0; uVar7 < *(ushort *)(iVar4 + 2) - 1; uVar7 = uVar7 + 1) {
      iVar8 = *(int *)(iVar4 + 0xc) + iVar10;
      uVar6 = (uint)*(byte *)(iVar8 + 0xe7) * 0x20 + 0x1f >> 5;
      uVar5 = uVar7 + 1 & 1;
      FUN_80022abc((&DAT_803414f8)[uVar5 * 2],param_3 + *(int *)(iVar8 + 0xd4),uVar6);
      local_48[uVar5] = (ushort)uVar6;
      iVar2 = *(int *)(iVar4 + 0xc) + iVar10;
      FUN_80022abc((&DAT_803414f8)[uVar5 * 2 + 1],*(uint *)(iVar2 + 0xd8),
                   (uint)*(byte *)(iVar2 + 0xe3) * 0x20 + 0x1f >> 5);
      FUN_80022a88(2);
      if ((param_5 & 0xff) == 0) {
        uVar5 = *puVar9;
        uVar6 = uVar7 & 1;
        pfVar3 = (float *)((uint)*(byte *)(iVar8 + 0x72) + (&DAT_803414f8)[uVar6 * 2]);
        FUN_8002a074((float *)(iVar1 + (uint)*(byte *)(iVar8 + 0x6c) * 0x30),
                     (float *)(iVar1 + (uint)*(byte *)(iVar8 + 0x6d) * 0x30),
                     (float *)(&DAT_803414fc)[uVar6 * 2],pfVar3,(int)pfVar3,
                     (uint)*(ushort *)(iVar8 + 0x70));
        FUN_80022a0c(uVar5,(&DAT_803414f8)[uVar6 * 2],(uint)local_48[uVar7 & 1]);
      }
      else {
        uVar5 = *puVar9;
        uVar6 = uVar7 & 1;
        pfVar3 = (float *)((uint)*(byte *)(iVar8 + 0x72) + (&DAT_803414f8)[uVar6 * 2]);
        FUN_8002a1e8((float *)(iVar1 + (uint)*(byte *)(iVar8 + 0x6c) * 0x30),
                     (float *)(iVar1 + (uint)*(byte *)(iVar8 + 0x6d) * 0x30),
                     (float *)(&DAT_803414fc)[uVar6 * 2],pfVar3,pfVar3,
                     (uint)*(ushort *)(iVar8 + 0x70));
        FUN_80022a0c(uVar5,(&DAT_803414f8)[uVar6 * 2],(uint)local_48[uVar7 & 1]);
      }
      iVar10 = iVar10 + 0x74;
      puVar9 = puVar9 + 1;
    }
    iVar4 = *(int *)(iVar4 + 0xc) + uVar7 * 0x74;
    FUN_80022a88(0);
    if ((param_5 & 0xff) == 0) {
      uVar6 = param_4[uVar7];
      uVar7 = uVar7 & 1;
      pfVar3 = (float *)((uint)*(byte *)(iVar4 + 0x72) + (&DAT_803414f8)[uVar7 * 2]);
      FUN_8002a074((float *)(iVar1 + (uint)*(byte *)(iVar4 + 0x6c) * 0x30),
                   (float *)(iVar1 + (uint)*(byte *)(iVar4 + 0x6d) * 0x30),
                   (float *)(&DAT_803414fc)[uVar7 * 2],pfVar3,(int)pfVar3,
                   (uint)*(ushort *)(iVar4 + 0x70));
      FUN_80022a0c(uVar6,(&DAT_803414f8)[uVar7 * 2],(uint)local_48[uVar7]);
    }
    else {
      uVar6 = param_4[uVar7];
      uVar7 = uVar7 & 1;
      pfVar3 = (float *)((uint)*(byte *)(iVar4 + 0x72) + (&DAT_803414f8)[uVar7 * 2]);
      FUN_8002a1e8((float *)(iVar1 + (uint)*(byte *)(iVar4 + 0x6c) * 0x30),
                   (float *)(iVar1 + (uint)*(byte *)(iVar4 + 0x6d) * 0x30),
                   (float *)(&DAT_803414fc)[uVar7 * 2],pfVar3,pfVar3,(uint)*(ushort *)(iVar4 + 0x70)
                  );
      FUN_80022a0c(uVar6,(&DAT_803414f8)[uVar7 * 2],(uint)local_48[uVar7]);
    }
    FUN_80022a88(0);
  }
  FUN_80286860();
  return;
}

