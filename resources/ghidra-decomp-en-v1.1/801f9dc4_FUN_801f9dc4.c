// Function: FUN_801f9dc4
// Entry: 801f9dc4
// Size: 112 bytes

void FUN_801f9dc4(int param_1)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801f9a74;
  bVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  if (1 < bVar1) {
    FUN_800201ac(0xd27,1);
    *(undefined *)(iVar2 + 0x68) = 1;
  }
  return;
}

