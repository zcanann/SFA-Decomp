// Function: FUN_802544d0
// Entry: 802544d0
// Size: 244 bytes

undefined4 FUN_802544d0(int param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  int iVar4;
  undefined *puVar5;
  int iVar6;
  
  iVar1 = param_1 * 0x40;
  puVar5 = &DAT_803ae400 + iVar1;
  uVar2 = FUN_8024377c();
  if ((*(uint *)(&DAT_803ae40c + iVar1) & 0x10) == 0) {
    *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) | 0x10;
    *(int *)(&DAT_803ae418 + iVar1) = param_2;
    FUN_80253188(param_1,puVar5);
    FUN_802437a4(uVar2);
    uVar2 = 1;
  }
  else {
    if (param_3 != 0) {
      iVar4 = *(int *)(&DAT_803ae424 + iVar1);
      puVar3 = puVar5;
      iVar6 = iVar4;
      if (0 < iVar4) {
        do {
          if (*(int *)(puVar3 + 0x28) == param_2) {
            FUN_802437a4(uVar2);
            return 0;
          }
          puVar3 = puVar3 + 8;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      *(int *)(puVar5 + iVar4 * 8 + 0x2c) = param_3;
      *(int *)(puVar5 + *(int *)(&DAT_803ae424 + iVar1) * 8 + 0x28) = param_2;
      *(int *)(&DAT_803ae424 + iVar1) = *(int *)(&DAT_803ae424 + iVar1) + 1;
    }
    FUN_802437a4(uVar2);
    uVar2 = 0;
  }
  return uVar2;
}

