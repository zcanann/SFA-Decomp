// Function: FUN_8028f844
// Entry: 8028f844
// Size: 160 bytes

uint FUN_8028f844(int param_1,ushort *param_2,uint param_3)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  undefined auStack_28 [20];
  
  uVar3 = 0;
  if ((param_1 == 0) || (param_2 == (ushort *)0x0)) {
    uVar3 = 0;
  }
  else {
    for (; uVar3 <= param_3; uVar3 = uVar3 + uVar2) {
      uVar1 = *param_2;
      if (uVar1 == 0) {
        *(undefined *)(param_1 + uVar3) = 0;
        return uVar3;
      }
      param_2 = param_2 + 1;
      uVar2 = FUN_8028f8e4((int)auStack_28,(uint)uVar1);
      if (param_3 < uVar3 + uVar2) {
        return uVar3;
      }
      FUN_80291f08(param_1 + uVar3,(int)auStack_28,uVar2);
    }
  }
  return uVar3;
}

