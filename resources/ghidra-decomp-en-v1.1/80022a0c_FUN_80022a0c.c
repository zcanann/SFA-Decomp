// Function: FUN_80022a0c
// Entry: 80022a0c
// Size: 124 bytes

void FUN_80022a0c(uint param_1,uint param_2,int param_3)

{
  int iVar1;
  
  if ((DAT_803de288 == 4) || (DAT_803de288 == 0)) {
    FUN_80242384(param_1);
  }
  else {
    if (param_3 == 0) {
      iVar1 = 0x1000;
    }
    else {
      iVar1 = param_3 << 5;
    }
    FUN_80003494(param_1,param_2,iVar1);
    FUN_802420e0(param_1,iVar1);
  }
  return;
}

