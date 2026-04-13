// Function: FUN_801e279c
// Entry: 801e279c
// Size: 568 bytes

void FUN_801e279c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  *(char *)(param_9 + 0xac) = (char)*(undefined2 *)(iVar4 + 0x72);
  uVar5 = FUN_801e1b78(param_9,iVar4);
  uVar1 = FUN_80020078(0x75);
  if (uVar1 == 0) {
    (**(code **)(*DAT_803dd72c + 0x44))(0xb,1);
    (**(code **)(*DAT_803dd72c + 0x50))(0xb,0,1);
    (**(code **)(*DAT_803dd72c + 0x50))(0xb,1,1);
    (**(code **)(*DAT_803dd72c + 0x50))(0xb,5,1);
    uVar2 = FUN_8004832c(0xb);
    FUN_80043658(uVar2,0);
    cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_9 + 0x34),1);
    if (cVar3 == '\0') {
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),1,1);
    }
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  else {
    if ((*(char *)(iVar4 + 0x80) == '\0') && ('\0' < *(char *)(iVar4 + 0x70))) {
      *(undefined *)(iVar4 + 0x80) = 1;
    }
    cVar3 = *(char *)(iVar4 + 0x70);
    if (cVar3 == '\x02') {
      FUN_801e18dc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    else if (cVar3 < '\x02') {
      if (cVar3 == '\0') {
        FUN_801e0018();
      }
      else if (-1 < cVar3) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
        *(undefined *)(iVar4 + 0x70) = 2;
      }
    }
    else if (cVar3 < '\x04') {
      (**(code **)(*DAT_803dd72c + 0x44))(0xb,1);
      *(undefined *)(param_9 + 0xac) = 0xff;
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
      *(undefined *)(iVar4 + 0x70) = 4;
    }
    FUN_801d84c4(iVar4 + 0xb0,1,-1,-1,0xa71,(int *)0xa4);
  }
  return;
}

