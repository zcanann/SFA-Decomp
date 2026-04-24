// Function: FUN_801f978c
// Entry: 801f978c
// Size: 112 bytes

void FUN_801f978c(int param_1)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801f943c;
  bVar1 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  if (1 < bVar1) {
    FUN_800200e8(0xd27,1);
    *(undefined *)(iVar2 + 0x68) = 1;
  }
  return;
}

