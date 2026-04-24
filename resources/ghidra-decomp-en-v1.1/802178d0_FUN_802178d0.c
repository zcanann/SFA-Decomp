// Function: FUN_802178d0
// Entry: 802178d0
// Size: 252 bytes

int FUN_802178d0(undefined4 param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  
  iVar2 = FUN_8002ba84();
  if (((iVar2 == 0) || (param_2 == (int *)0x0)) ||
     (cVar4 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x40))(), cVar4 == '\0')) {
    iVar1 = FUN_8002bac4();
    if ((iVar1 == 0) ||
       (((iVar2 = FUN_80297a08(iVar1), iVar2 == 0 || ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)) &&
        (iVar2 = iVar1, (*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)))) {
      iVar2 = 0;
    }
  }
  else {
    uVar3 = (uint)DAT_803dc070;
    iVar1 = *param_2;
    *param_2 = iVar1 - uVar3;
    if ((int)(iVar1 - uVar3) < 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x34))(iVar2,0,0);
      *param_2 = 600;
    }
  }
  return iVar2;
}

