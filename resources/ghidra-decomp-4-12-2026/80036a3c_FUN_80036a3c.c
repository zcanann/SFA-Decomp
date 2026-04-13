// Function: FUN_80036a3c
// Entry: 80036a3c
// Size: 172 bytes

void FUN_80036a3c(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,undefined4 param_8)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dd860; iVar2 = iVar2 + 1) {
    psVar1 = *(short **)(DAT_803dd864 + iVar3);
    if (((*(uint *)(*(int *)(psVar1 + 0x28) + 0x44) & 0x40) == 0) &&
       (*(char *)(psVar1 + 0x57) != 'd')) {
      FUN_8002c85c(psVar1,*(int *)(psVar1 + 0x28),param_3,param_4,param_5,param_6,param_7,param_8);
    }
    iVar3 = iVar3 + 4;
  }
  iVar3 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dd860; iVar2 = iVar2 + 1) {
    FUN_80032508(*(ushort **)(DAT_803dd864 + iVar3),1);
    iVar3 = iVar3 + 4;
  }
  return;
}

