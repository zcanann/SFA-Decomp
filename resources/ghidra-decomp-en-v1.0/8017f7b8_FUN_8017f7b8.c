// Function: FUN_8017f7b8
// Entry: 8017f7b8
// Size: 272 bytes

void FUN_8017f7b8(int param_1,undefined4 param_2)

{
  char cVar2;
  int iVar1;
  int *piVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  piVar3 = *(int **)(param_1 + 0xb8);
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    iVar1 = FUN_8002bdf4(0x30,param_2);
    *(undefined *)(iVar1 + 0x1a) = 0x14;
    *(undefined2 *)(iVar1 + 0x2c) = 0xffff;
    *(undefined2 *)(iVar1 + 0x1c) = 0xffff;
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined2 *)(iVar1 + 0x24) = 0xffff;
    *(undefined *)(iVar1 + 4) = *(undefined *)(iVar4 + 4);
    *(undefined *)(iVar1 + 6) = *(undefined *)(iVar4 + 6);
    *(undefined *)(iVar1 + 5) = *(undefined *)(iVar4 + 5);
    *(char *)(iVar1 + 7) = *(char *)(iVar4 + 7) + -0xf;
    iVar4 = FUN_8002df90(iVar1,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                         *(undefined4 *)(param_1 + 0x30));
    if (iVar4 == 0) {
      FUN_80023800(iVar1);
      *piVar3 = 0;
    }
    else {
      FUN_80037d2c(param_1,iVar4,0);
      *piVar3 = iVar4;
    }
  }
  return;
}

