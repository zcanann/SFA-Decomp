// Function: FUN_8021a714
// Entry: 8021a714
// Size: 248 bytes

void FUN_8021a714(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  piVar3 = *(int **)(iVar2 + 0xb8);
  if (param_6 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e69f0);
    iVar1 = *piVar3;
    if (iVar1 != 0) {
      FUN_8003842c(iVar2,0,iVar1 + 0xc,iVar1 + 0x10,iVar1 + 0x14,0);
      FUN_8003b8f4((double)FLOAT_803e69f0,*piVar3,(int)uVar4,param_3,param_4,param_5);
      iVar2 = piVar3[1];
      if (iVar2 != 0) {
        *(undefined2 *)(iVar2 + 2) = *(undefined2 *)(*piVar3 + 2);
        *(undefined2 *)(iVar2 + 4) = *(undefined2 *)(*piVar3 + 4);
        FUN_8003842c(*piVar3,0,iVar2 + 0xc,iVar2 + 0x10,iVar2 + 0x14,0);
        FUN_8003b8f4((double)FLOAT_803e69f0,iVar2,(int)uVar4,param_3,param_4,param_5);
      }
    }
  }
  FUN_80286124();
  return;
}

