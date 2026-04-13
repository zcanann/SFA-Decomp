// Function: FUN_8003811c
// Entry: 8003811c
// Size: 188 bytes

undefined4 FUN_8003811c(int param_1)

{
  uint uVar1;
  int iVar2;
  
  if ((((*(int *)(*(int *)(param_1 + 0x50) + 0x40) != 0) &&
       (uVar1 = FUN_80014b50(0), (uVar1 & 0x100) == 0)) && ((*(byte *)(param_1 + 0xaf) & 1) != 0))
     && (((*(byte *)(param_1 + 0xaf) & 8) == 0 &&
         (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x1c))(), iVar2 == 0)))) {
    iVar2 = FUN_8002bac4();
    iVar2 = FUN_80297300(iVar2);
    if ((iVar2 == -1) || (iVar2 == 0x40)) {
      FUN_80014b68(0,0x100);
      return 1;
    }
  }
  return 0;
}

