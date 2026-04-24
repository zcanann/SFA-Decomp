// Function: FUN_8024b698
// Entry: 8024b698
// Size: 172 bytes

undefined4 FUN_8024b698(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_8024b428(param_1,&LAB_8024b744);
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = FUN_8024377c();
    while (((iVar1 = *(int *)(param_1 + 0xc), 1 < iVar1 + 1U && (iVar1 != 10)) &&
           ((iVar1 != 3 ||
            (((iVar1 = *(int *)(param_1 + 8), 1 < iVar1 - 4U && (iVar1 != 0xd)) && (iVar1 != 0xf))))
           ))) {
      FUN_80246a60(&DAT_803ddf00);
    }
    FUN_802437a4(uVar2);
    uVar2 = 0;
  }
  return uVar2;
}

