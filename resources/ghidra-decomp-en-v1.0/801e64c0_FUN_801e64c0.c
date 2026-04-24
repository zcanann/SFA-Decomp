// Function: FUN_801e64c0
// Entry: 801e64c0
// Size: 372 bytes

void FUN_801e64c0(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_8002b9ec();
  iVar2 = FUN_802966cc();
  if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0x18b), iVar2 == 0)) {
    FUN_80295cf4(uVar1,0);
  }
  if (*(int *)(param_1 + 0xf4) == 0) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0,1);
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),5,1);
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),6,1);
    FUN_800200e8(0x617,1);
    FUN_80088c94(7,1);
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  iVar2 = FUN_8001ffb4(0xd21);
  if ((iVar2 == 0) || (*(int *)(param_1 + 0xf8) != 0)) {
    iVar2 = FUN_8001ffb4(0xd21);
    if ((iVar2 == 0) && (*(int *)(param_1 + 0xf8) != 0)) {
      *(undefined4 *)(param_1 + 0xf8) = 0;
    }
  }
  else {
    FUN_800887f8(0);
    FUN_80008cbc(param_1,param_1,0x1c8,0);
    FUN_80008cbc(param_1,param_1,0x1cb,0);
    *(undefined4 *)(param_1 + 0xf8) = 1;
  }
  return;
}

