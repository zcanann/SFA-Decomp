// Function: FUN_801926f8
// Entry: 801926f8
// Size: 236 bytes

void FUN_801926f8(int param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar1 = FUN_8005b068(iVar1);
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if ((((iVar2 == 0x49b2f) || (iVar2 == 0x49b67)) && (iVar1 != 0)) &&
     ((uVar3 = FUN_80020078(*(uint *)(iVar4 + 8)), *(uint *)(iVar4 + 0xc) != uVar3 &&
      (*(char *)(iVar4 + 0x10) == '\0')))) {
    FUN_801924d0();
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  uVar3 = FUN_80020078(*(uint *)(iVar4 + 8));
  *(uint *)(iVar4 + 0xc) = uVar3;
  if (iVar1 == 0) {
    *(undefined *)(iVar4 + 0x10) = 1;
  }
  else if (*(char *)(iVar4 + 0x10) != '\0') {
    FUN_801924d0();
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  return;
}

