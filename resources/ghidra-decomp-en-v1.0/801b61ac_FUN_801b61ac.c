// Function: FUN_801b61ac
// Entry: 801b61ac
// Size: 168 bytes

void FUN_801b61ac(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_8002b9ec();
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_801b5f1c(param_1,iVar2);
  FUN_801b5d48(param_1,iVar2);
  if (*(char *)(iVar2 + 0x5f) == '\0') {
    iVar2 = FUN_8001ffb4(0x1ef);
    if ((iVar2 != 0) && (iVar2 = FUN_80296458(uVar1), iVar2 != 0)) {
      FUN_800200e8(0x1e8,1);
    }
  }
  else {
    FUN_80065574(0x11,0,0);
  }
  return;
}

