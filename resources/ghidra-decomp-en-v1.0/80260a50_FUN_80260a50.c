// Function: FUN_80260a50
// Entry: 80260a50
// Size: 196 bytes

undefined4 FUN_80260a50(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = param_1 * 0x110;
  if ((&DAT_803af1e0)[param_1 * 0x44] == 0) {
    uVar1 = 0xfffffffd;
  }
  else {
    iVar3 = *(int *)(&DAT_803af264 + iVar2);
    *(short *)(iVar3 + 0x1ffa) = *(short *)(iVar3 + 0x1ffa) + 1;
    FUN_80260b14(iVar3,0x1ffc,iVar3 + 0x1ffc,iVar3 + 0x1ffe);
    FUN_80241a1c(iVar3,0x2000);
    *(undefined4 *)(&DAT_803af2b8 + iVar2) = param_2;
    uVar1 = FUN_8025ec14(param_1,*(int *)(&DAT_803af1ec + iVar2) *
                                 ((uint)(iVar3 - (&DAT_803af260)[param_1 * 0x44]) >> 0xd),
                         &LAB_80260988);
  }
  return uVar1;
}

