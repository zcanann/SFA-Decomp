// Function: FUN_80291e40
// Entry: 80291e40
// Size: 260 bytes

void FUN_80291e40(void)

{
  double dVar1;
  double dVar2;
  double dVar3;
  undefined auStack52 [4];
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  
  dVar1 = (double)FUN_8028604c();
  dVar3 = ABS(dVar1);
  if ((double)FLOAT_803e79a0 <= dVar3) {
    dVar2 = dVar1;
    if (dVar3 < (double)FLOAT_803e79ac) {
      local_28 = (longlong)(int)dVar1;
      uStack44 = (int)dVar1 ^ 0x80000000;
      local_30 = 0x43300000;
      dVar2 = (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e79b8);
      if ((dVar1 < (double)FLOAT_803e79a4) && (dVar1 != dVar2)) {
        dVar2 = (double)(float)(dVar2 - (double)FLOAT_803e79b0);
      }
    }
  }
  else {
    FUN_80291ce4(dVar3,auStack52);
    dVar2 = (double)FUN_80291cc8(auStack52);
    if (dVar1 < (double)FLOAT_803e79a4) {
      if (dVar1 == -dVar2) {
        dVar2 = -dVar2;
      }
      else {
        dVar2 = (double)(float)((double)FLOAT_803e79a8 - dVar2);
      }
    }
  }
  FUN_80286098(dVar2);
  return;
}

