// Function: FUN_80284410
// Entry: 80284410
// Size: 136 bytes

void FUN_80284410(int param_1,uint param_2,int param_3,uint param_4,undefined4 param_5,
                 undefined4 param_6)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 auStack_20 [2];
  
  iVar2 = FUN_80284d9c(param_4,auStack_20);
  uVar1 = param_3 + (param_2 & 0x1f) + 0x1f & 0xffffffe0;
  uVar3 = param_1 + (param_2 & 0xffffffe0);
  FUN_80242114(uVar3,uVar1);
  FUN_8028479c(uVar3,iVar2 + (param_2 & 0xffffffe0),uVar1,1,param_5,param_6);
  return;
}

