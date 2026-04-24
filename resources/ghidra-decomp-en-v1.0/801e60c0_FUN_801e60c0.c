// Function: FUN_801e60c0
// Entry: 801e60c0
// Size: 340 bytes

void FUN_801e60c0(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = FUN_8002b9ec();
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = (**(code **)(*DAT_803dcaac + 0x8c))();
  FUN_802968ac(uVar1,-param_2);
  switch(*(undefined *)(iVar3 + 1)) {
  case 0:
    FUN_80296afc(uVar1,2);
    break;
  case 1:
    FUN_80296afc(uVar1,8);
    break;
  case 2:
    FUN_80296afc(uVar1,4);
    break;
  case 3:
    FUN_80296afc(uVar1,0x1c);
    break;
  case 4:
    FUN_8001ff3c(0x66c);
    break;
  case 5:
    FUN_8001ff3c(0x86a);
    break;
  case 6:
    FUN_8001ff3c(0xc1);
    break;
  case 7:
    FUN_8001ff3c(0x13d);
    FUN_8001ff3c(0x5d6);
    break;
  case 8:
    FUN_8001ff3c(0x3f5);
    break;
  case 0x17:
    *(undefined *)(iVar2 + 10) = 10;
  }
  if (*(short *)(&DAT_80327fd8 + *(char *)(iVar3 + 1) * 0xc) != -1) {
    FUN_800200e8((int)*(short *)(&DAT_80327fd8 + *(char *)(iVar3 + 1) * 0xc),1);
  }
  return;
}

