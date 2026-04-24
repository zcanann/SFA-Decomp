// Function: FUN_80022abc
// Entry: 80022abc
// Size: 80 bytes

void FUN_80022abc(uint param_1,uint param_2,int param_3)

{
  int iVar1;
  
  if ((DAT_803de288 == 4) || (DAT_803de288 == 0)) {
    FUN_80242360();
  }
  else {
    if (param_3 == 0) {
      iVar1 = 0x1000;
    }
    else {
      iVar1 = param_3 << 5;
    }
    FUN_80003494(param_1,param_2,iVar1);
  }
  return;
}

