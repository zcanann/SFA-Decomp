// Function: FUN_80203000
// Entry: 80203000
// Size: 324 bytes

void FUN_80203000(undefined4 param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_2 + 0x40c);
  if (((*(byte *)(iVar1 + 0x14) & 1) != 0) && (*(int *)(param_2 + 0x2d0) != 0)) {
    FUN_80202ef0();
  }
  if ((*(byte *)(iVar1 + 0x14) & 2) != 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x345,0,2,0xffffffff,0);
  }
  if ((*(byte *)(iVar1 + 0x14) & 4) != 0) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x343,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 10);
  }
  *(undefined *)(iVar1 + 0x14) = 0;
  return;
}

