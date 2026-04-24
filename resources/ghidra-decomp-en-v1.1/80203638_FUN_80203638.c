// Function: FUN_80203638
// Entry: 80203638
// Size: 324 bytes

void FUN_80203638(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_10 + 0x40c);
  if (((*(byte *)(iVar1 + 0x14) & 1) != 0) && (*(int *)(param_10 + 0x2d0) != 0)) {
    FUN_80203528(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  if ((*(byte *)(iVar1 + 0x14) & 2) != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
  }
  if ((*(byte *)(iVar1 + 0x14) & 4) != 0) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x343,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 10);
  }
  *(undefined *)(iVar1 + 0x14) = 0;
  return;
}

