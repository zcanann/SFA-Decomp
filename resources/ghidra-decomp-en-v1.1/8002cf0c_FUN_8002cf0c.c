// Function: FUN_8002cf0c
// Entry: 8002cf0c
// Size: 116 bytes

void FUN_8002cf0c(int param_1)

{
  int iVar1;
  int iVar2;
  
  if ((*(ushort *)(param_1 + 0xb0) & 0x10) != 0) {
    iVar1 = 0;
    for (iVar2 = iRam803dd800; (iVar2 != 0 && (*(char *)(param_1 + 0xae) < *(char *)(iVar2 + 0xae)))
        ; iVar2 = *(int *)(iVar2 + sRam803dd7fe)) {
      iVar1 = iVar2;
    }
    FUN_80013b40((short *)&DAT_803dd7fc,iVar1,param_1);
  }
  return;
}

