// Function: FUN_8024bdfc
// Entry: 8024bdfc
// Size: 172 bytes

undefined4 FUN_8024bdfc(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_8024bb8c(param_1,&LAB_8024bea8);
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    FUN_80243e74();
    while (((iVar1 = param_1[3], 1 < iVar1 + 1U && (iVar1 != 10)) &&
           ((iVar1 != 3 ||
            (((iVar1 = param_1[2], 1 < iVar1 - 4U && (iVar1 != 0xd)) && (iVar1 != 0xf))))))) {
      FUN_802471c4((int *)&DAT_803deb80);
    }
    FUN_80243e9c();
    uVar2 = 0;
  }
  return uVar2;
}

