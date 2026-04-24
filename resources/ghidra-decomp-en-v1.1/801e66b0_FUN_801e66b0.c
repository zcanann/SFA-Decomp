// Function: FUN_801e66b0
// Entry: 801e66b0
// Size: 340 bytes

void FUN_801e66b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  iVar1 = FUN_8002bac4();
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar2 = (**(code **)(*DAT_803dd72c + 0x8c))();
  uVar4 = FUN_8029700c(iVar1,-param_10);
  switch(*(undefined *)(iVar3 + 1)) {
  case 0:
    FUN_8029725c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,2);
    break;
  case 1:
    FUN_8029725c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,8);
    break;
  case 2:
    FUN_8029725c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,4);
    break;
  case 3:
    FUN_8029725c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x1c);
    break;
  case 4:
    FUN_80020000(0x66c);
    break;
  case 5:
    FUN_80020000(0x86a);
    break;
  case 6:
    FUN_80020000(0xc1);
    break;
  case 7:
    FUN_80020000(0x13d);
    FUN_80020000(0x5d6);
    break;
  case 8:
    FUN_80020000(0x3f5);
    break;
  case 0x17:
    *(undefined *)(iVar2 + 10) = 10;
  }
  if ((int)*(short *)(&DAT_80328c18 + *(char *)(iVar3 + 1) * 0xc) != 0xffffffff) {
    FUN_800201ac((int)*(short *)(&DAT_80328c18 + *(char *)(iVar3 + 1) * 0xc),1);
  }
  return;
}

