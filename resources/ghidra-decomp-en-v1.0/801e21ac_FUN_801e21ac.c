// Function: FUN_801e21ac
// Entry: 801e21ac
// Size: 568 bytes

void FUN_801e21ac(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(char *)(param_1 + 0xac) = (char)*(undefined2 *)(iVar4 + 0x72);
  FUN_801e1588(param_1,iVar4);
  iVar1 = FUN_8001ffb4(0x75);
  if (iVar1 == 0) {
    (**(code **)(*DAT_803dcaac + 0x44))(0xb,1);
    (**(code **)(*DAT_803dcaac + 0x50))(0xb,0,1);
    (**(code **)(*DAT_803dcaac + 0x50))(0xb,1,1);
    (**(code **)(*DAT_803dcaac + 0x50))(0xb,5,1);
    uVar2 = FUN_800481b0(0xb);
    FUN_80043560(uVar2,0);
    cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))(*(undefined *)(param_1 + 0x34),1);
    if (cVar3 == '\0') {
      (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x34),1,1);
    }
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  else {
    if ((*(char *)(iVar4 + 0x80) == '\0') && ('\0' < *(char *)(iVar4 + 0x70))) {
      *(undefined *)(iVar4 + 0x80) = 1;
    }
    cVar3 = *(char *)(iVar4 + 0x70);
    if (cVar3 == '\x02') {
      FUN_801e12ec(param_1);
    }
    else if (cVar3 < '\x02') {
      if (cVar3 == '\0') {
        FUN_801dfa28(param_1);
      }
      else if (-1 < cVar3) {
        (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
        *(undefined *)(iVar4 + 0x70) = 2;
      }
    }
    else if (cVar3 < '\x04') {
      (**(code **)(*DAT_803dcaac + 0x44))(0xb,1);
      *(undefined *)(param_1 + 0xac) = 0xff;
      (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
      *(undefined *)(iVar4 + 0x70) = 4;
    }
    FUN_801d7ed4(iVar4 + 0xb0,1,0xffffffff,0xffffffff,0xa71,0xa4);
  }
  return;
}

