// Function: FUN_80283cac
// Entry: 80283cac
// Size: 136 bytes

void FUN_80283cac(int param_1,uint param_2,int param_3,undefined4 param_4,undefined4 param_5,
                 undefined4 param_6)

{
  uint uVar1;
  int iVar2;
  undefined auStack32 [8];
  
  iVar2 = FUN_80284638(param_4,auStack32);
  uVar1 = param_3 + (param_2 & 0x1f) + 0x1f & 0xffffffe0;
  param_1 = param_1 + (param_2 & 0xffffffe0);
  FUN_80241a1c(param_1,uVar1);
  FUN_80284038(param_1,iVar2 + (param_2 & 0xffffffe0),uVar1,1,param_5,param_6);
  return;
}

