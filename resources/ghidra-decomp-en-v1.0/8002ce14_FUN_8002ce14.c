// Function: FUN_8002ce14
// Entry: 8002ce14
// Size: 116 bytes

void FUN_8002ce14(int param_1)

{
  int iVar1;
  int iVar2;
  
  if ((*(ushort *)(param_1 + 0xb0) & 0x10) != 0) {
    iVar1 = 0;
    for (iVar2 = iRam803dcb80; (iVar2 != 0 && (*(char *)(param_1 + 0xae) < *(char *)(iVar2 + 0xae)))
        ; iVar2 = *(int *)(iVar2 + sRam803dcb7e)) {
      iVar1 = iVar2;
    }
    FUN_80013b20(&DAT_803dcb7c,iVar1);
  }
  return;
}

