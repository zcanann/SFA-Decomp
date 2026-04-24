// Function: FUN_8028f7e0
// Entry: 8028f7e0
// Size: 124 bytes

undefined4 FUN_8028f7e0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_802918c0(&DAT_803323d0,0xffffffff);
  if (iVar1 < 0) {
    uVar2 = FUN_8028f920(FUN_8028f8c8,&DAT_803323d0,param_1,param_2);
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

