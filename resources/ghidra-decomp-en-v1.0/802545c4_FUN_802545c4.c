// Function: FUN_802545c4
// Entry: 802545c4
// Size: 220 bytes

undefined4 FUN_802545c4(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  code *pcVar4;
  
  iVar1 = param_1 * 0x40;
  uVar3 = FUN_8024377c();
  if ((*(uint *)(&DAT_803ae40c + iVar1) & 0x10) == 0) {
    FUN_802437a4(uVar3);
    uVar3 = 0;
  }
  else {
    *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) & 0xffffffef;
    FUN_80253188(param_1,&DAT_803ae400 + iVar1);
    if (0 < *(int *)(&DAT_803ae424 + iVar1)) {
      iVar2 = *(int *)(&DAT_803ae424 + iVar1) + -1;
      pcVar4 = *(code **)(&DAT_803ae42c + iVar1);
      *(int *)(&DAT_803ae424 + iVar1) = iVar2;
      if (0 < iVar2) {
        FUN_8028f2cc(&DAT_803ae428 + iVar1,&DAT_803ae430 + iVar1,
                     *(int *)(&DAT_803ae424 + iVar1) << 3);
      }
      (*pcVar4)(param_1,0);
    }
    FUN_802437a4(uVar3);
    uVar3 = 1;
  }
  return uVar3;
}

