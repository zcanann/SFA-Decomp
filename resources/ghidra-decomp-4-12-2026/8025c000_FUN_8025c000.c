// Function: FUN_8025c000
// Entry: 8025c000
// Size: 420 bytes

void FUN_8025c000(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = 10;
  iVar2 = 5;
  if (param_1 != 0) {
    uVar1 = 0;
    iVar2 = 0;
  }
  if (param_2 == 2) {
    FUN_8025c1a4(param_1,uVar1,0xc,8,0xf);
    FUN_8025c224(param_1,7,4,iVar2,7);
  }
  else if (param_2 < 2) {
    if (param_2 == 0) {
      FUN_8025c1a4(param_1,0xf,8,uVar1,0xf);
      FUN_8025c224(param_1,7,4,iVar2,7);
    }
    else if (-1 < param_2) {
      FUN_8025c1a4(param_1,uVar1,8,9,0xf);
      FUN_8025c224(param_1,7,7,7,iVar2);
    }
  }
  else if (param_2 == 4) {
    FUN_8025c1a4(param_1,0xf,0xf,0xf,uVar1);
    FUN_8025c224(param_1,7,7,7,iVar2);
  }
  else if (param_2 < 4) {
    FUN_8025c1a4(param_1,0xf,0xf,0xf,8);
    FUN_8025c224(param_1,7,7,7,4);
  }
  FUN_8025c2a8(param_1,0,0,0,1,0);
  FUN_8025c368(param_1,0,0,0,1,0);
  return;
}

