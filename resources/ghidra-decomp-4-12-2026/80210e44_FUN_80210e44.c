// Function: FUN_80210e44
// Entry: 80210e44
// Size: 436 bytes

void FUN_80210e44(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  iVar1 = FUN_8002bac4();
  switch(*(undefined *)(iVar4 + 8)) {
  case 0:
    break;
  default:
    *(undefined *)(iVar4 + 8) = 2;
    break;
  case 2:
    uVar2 = FUN_80020078(0x4a0);
    if (uVar2 != 0) {
      FUN_800201ac(0x4ba,1);
    }
    iVar1 = FUN_80297a08(iVar1);
    if (iVar1 != 0) {
      FUN_800201ac(0x49d,1);
      FUN_800201ac(0x497,1);
      *(undefined *)(iVar4 + 8) = 3;
      FUN_80043604(0,0,1);
    }
    break;
  case 3:
    FUN_80210d38(param_9,iVar4);
    break;
  case 4:
    FUN_800201ac(0x4ba,0);
    *(undefined *)(iVar4 + 8) = 7;
    FUN_80080404((float *)(iVar4 + 4),10);
    break;
  case 5:
    *(undefined *)(iVar4 + 8) = 2;
    break;
  case 7:
    iVar1 = FUN_80080434((float *)(iVar4 + 4));
    if (iVar1 != 0) {
      *(undefined *)(iVar4 + 8) = 8;
    }
    break;
  case 8:
    FUN_80043604(0,0,1);
    FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xc);
    uVar3 = FUN_8004832c(0xc);
    FUN_80043658(uVar3,0);
    FUN_800201ac(0xd73,0);
    FUN_800201ac(0x983,0);
    FUN_800201ac(0xe23,0);
    FUN_800201ac(0xe1d,0);
    FUN_800201ac(0xdb8,0);
    FUN_800201ac(0x984,0);
    FUN_800201ac(0x458,0);
    *(undefined *)(iVar4 + 8) = 0;
  }
  return;
}

