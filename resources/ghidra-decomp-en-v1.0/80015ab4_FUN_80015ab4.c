// Function: FUN_80015ab4
// Entry: 80015ab4
// Size: 276 bytes

int FUN_80015ab4(undefined4 param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined auStack88 [52];
  int local_24;
  
  if (param_2 != (int *)0x0) {
    *param_2 = 0;
  }
  FUN_8024b418(1);
  iVar2 = FUN_80248b9c(param_1,auStack88);
  if (iVar2 == 0) {
    iVar2 = 0;
  }
  else {
    uVar1 = local_24 + 0x1fU & 0xffffffe0;
    iVar2 = FUN_80023cc8(uVar1,0x7d7d7d7d,0);
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      iVar3 = FUN_80015850(auStack88,iVar2,uVar1,0);
      if (iVar3 == -1) {
        FUN_80023800(iVar2);
        iVar2 = 0;
      }
      else {
        iVar3 = FUN_80248c64(auStack88);
        if (iVar3 == 0) {
          FUN_80023800(iVar2);
          iVar2 = 0;
        }
        else {
          FUN_80241a1c(iVar2,local_24);
          if (param_2 != (int *)0x0) {
            *param_2 = local_24;
          }
        }
      }
    }
  }
  return iVar2;
}

