// Function: FUN_801b6760
// Entry: 801b6760
// Size: 168 bytes

void FUN_801b6760(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar1 = FUN_8002bac4();
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_801b64d0(param_1,iVar3);
  FUN_801b62fc();
  if (*(char *)(iVar3 + 0x5f) == '\0') {
    uVar2 = FUN_80020078(0x1ef);
    if ((uVar2 != 0) && (iVar1 = FUN_80296bb8(iVar1), iVar1 != 0)) {
      FUN_800201ac(0x1e8,1);
    }
  }
  else {
    FUN_800656f0(0x11,0,0);
  }
  return;
}

