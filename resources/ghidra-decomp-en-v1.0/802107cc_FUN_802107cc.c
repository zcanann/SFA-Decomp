// Function: FUN_802107cc
// Entry: 802107cc
// Size: 436 bytes

void FUN_802107cc(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_8002b9ec();
  switch(*(undefined *)(iVar3 + 8)) {
  case 0:
    break;
  default:
    *(undefined *)(iVar3 + 8) = 2;
    break;
  case 2:
    iVar2 = FUN_8001ffb4(0x4a0);
    if (iVar2 != 0) {
      FUN_800200e8(0x4ba,1);
    }
    iVar2 = FUN_802972a8(uVar1);
    if (iVar2 != 0) {
      FUN_800200e8(0x49d,1);
      FUN_800200e8(0x497,1);
      *(undefined *)(iVar3 + 8) = 3;
      FUN_8004350c(0,0,1);
    }
    break;
  case 3:
    FUN_802106c0(param_1,iVar3);
    break;
  case 4:
    FUN_800200e8(0x4ba,0);
    *(undefined *)(iVar3 + 8) = 7;
    FUN_80080178(iVar3 + 4,10);
    break;
  case 5:
    *(undefined *)(iVar3 + 8) = 2;
    break;
  case 7:
    iVar2 = FUN_800801a8(iVar3 + 4);
    if (iVar2 != 0) {
      *(undefined *)(iVar3 + 8) = 8;
    }
    break;
  case 8:
    FUN_8004350c(0,0,1);
    FUN_80042f78(0xc);
    uVar1 = FUN_800481b0(0xc);
    FUN_80043560(uVar1,0);
    FUN_800200e8(0xd73,0);
    FUN_800200e8(0x983,0);
    FUN_800200e8(0xe23,0);
    FUN_800200e8(0xe1d,0);
    FUN_800200e8(0xdb8,0);
    FUN_800200e8(0x984,0);
    FUN_800200e8(0x458,0);
    *(undefined *)(iVar3 + 8) = 0;
  }
  return;
}

