// Function: FUN_80243108
// Entry: 80243108
// Size: 512 bytes

void FUN_80243108(byte param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined2 uVar1;
  undefined4 uVar2;
  
  if ((*(uint *)(param_2 + 0x19c) & 2) == 0) {
    FUN_8007d858();
  }
  else {
    if (*(int *)(&DAT_803adfd0 + (uint)param_1 * 4) != 0) {
      FUN_802464f8();
      (**(code **)(&DAT_803adfd0 + (uint)param_1 * 4))(param_1,param_2,param_3,param_4);
      FUN_80246538();
      FUN_802469dc();
      FUN_80242a8c(param_2);
    }
    if (param_1 == 8) {
      FUN_80242a8c(param_2);
    }
    FUN_8007d858();
  }
  FUN_8007d858();
  FUN_80242c4c(param_2);
  FUN_8007d858();
  FUN_802473b4();
  FUN_8007d858();
  switch(param_1) {
  case 2:
    FUN_8007d858();
    break;
  case 3:
    FUN_8007d858();
    break;
  case 5:
    FUN_8007d858();
    break;
  case 6:
    FUN_8007d858();
    break;
  case 0xf:
    FUN_8007d858();
    uVar1 = DAT_cc005030;
    uVar1 = DAT_cc005032;
    FUN_8007d858();
    uVar1 = DAT_cc005020;
    uVar1 = DAT_cc005022;
    FUN_8007d858();
    uVar2 = DAT_cc006014;
    FUN_8007d858();
  }
  FUN_8007d858();
  FUN_80294da8();
  return;
}

