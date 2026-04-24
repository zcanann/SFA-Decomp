// Function: FUN_80038024
// Entry: 80038024
// Size: 188 bytes

undefined4 FUN_80038024(int param_1)

{
  uint uVar1;
  int iVar2;
  
  if ((((*(int *)(*(int *)(param_1 + 0x50) + 0x40) != 0) &&
       (uVar1 = FUN_80014b24(0), (uVar1 & 0x100) == 0)) && ((*(byte *)(param_1 + 0xaf) & 1) != 0))
     && (((*(byte *)(param_1 + 0xaf) & 8) == 0 &&
         (iVar2 = (**(code **)(*DAT_803dca68 + 0x1c))(), iVar2 == 0)))) {
    FUN_8002b9ec();
    iVar2 = FUN_80296ba0();
    if ((iVar2 == -1) || (iVar2 == 0x40)) {
      FUN_80014b3c(0,0x100);
      return 1;
    }
  }
  return 0;
}

