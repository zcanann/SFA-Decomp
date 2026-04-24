// Function: FUN_8019217c
// Entry: 8019217c
// Size: 236 bytes

void FUN_8019217c(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14));
  iVar1 = FUN_8005aeec();
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if ((((iVar2 == 0x49b2f) || (iVar2 == 0x49b67)) && (iVar1 != 0)) &&
     ((iVar2 = FUN_8001ffb4(*(undefined4 *)(iVar4 + 8)), *(int *)(iVar4 + 0xc) != iVar2 &&
      (*(char *)(iVar4 + 0x10) == '\0')))) {
    FUN_80191f54(param_1,iVar4);
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  uVar3 = FUN_8001ffb4(*(undefined4 *)(iVar4 + 8));
  *(undefined4 *)(iVar4 + 0xc) = uVar3;
  if (iVar1 == 0) {
    *(undefined *)(iVar4 + 0x10) = 1;
  }
  else if (*(char *)(iVar4 + 0x10) != '\0') {
    FUN_80191f54(param_1,iVar4);
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  return;
}

