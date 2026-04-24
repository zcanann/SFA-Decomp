// Function: FUN_8025b89c
// Entry: 8025b89c
// Size: 420 bytes

void FUN_8025b89c(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  uVar1 = 10;
  uVar2 = 5;
  if (param_1 != 0) {
    uVar1 = 0;
    uVar2 = 0;
  }
  if (param_2 == 2) {
    FUN_8025ba40(param_1,uVar1,0xc,8,0xf);
    FUN_8025bac0(param_1,7,4,uVar2,7);
  }
  else if (param_2 < 2) {
    if (param_2 == 0) {
      FUN_8025ba40(param_1,0xf,8,uVar1,0xf);
      FUN_8025bac0(param_1,7,4,uVar2,7);
    }
    else if (-1 < param_2) {
      FUN_8025ba40(param_1,uVar1,8,9,0xf);
      FUN_8025bac0(param_1,7,7,7,uVar2);
    }
  }
  else if (param_2 == 4) {
    FUN_8025ba40(param_1,0xf,0xf,0xf,uVar1);
    FUN_8025bac0(param_1,7,7,7,uVar2);
  }
  else if (param_2 < 4) {
    FUN_8025ba40(param_1,0xf,0xf,0xf,8);
    FUN_8025bac0(param_1,7,7,7,4);
  }
  FUN_8025bb44(param_1,0,0,0,1,0);
  FUN_8025bc04(param_1,0,0,0,1,0);
  return;
}

