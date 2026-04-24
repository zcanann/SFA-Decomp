// Function: FUN_801f076c
// Entry: 801f076c
// Size: 352 bytes

void FUN_801f076c(int param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int local_18 [5];
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x4c) + 0x19);
  if ((((cVar1 != '\b') && (cVar1 < '\b')) && (cVar1 == '\0')) &&
     (((*(int *)(param_1 + 0xf4) == 0 && (iVar3 = FUN_8001ffb4(0xa4), iVar3 == 0)) &&
      (iVar3 = FUN_8001ffb4(0x78), iVar3 == 0)))) {
    piVar4 = (int *)FUN_80036f50(6,local_18);
    bVar2 = false;
    if (0 < local_18[0]) {
      do {
        if (*(short *)(*piVar4 + 0x46) == 0x139) {
          bVar2 = true;
        }
        piVar4 = piVar4 + 1;
        local_18[0] = local_18[0] + -1;
      } while (local_18[0] != 0);
    }
    if (bVar2) {
      if (*(int *)(param_1 + 0xf8) == 0) {
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        *(undefined4 *)(param_1 + 0xf4) = 1;
        FUN_800200e8(0xa4,1);
      }
      else {
        (**(code **)(*DAT_803dca4c + 0xc))(0x50,1);
      }
    }
    else {
      *(undefined4 *)(param_1 + 0xf8) = 0x14;
      (**(code **)(*DAT_803dca4c + 0xc))(0x50,1);
    }
    iVar3 = *(int *)(param_1 + 0xf8) + -1;
    *(int *)(param_1 + 0xf8) = iVar3;
    if (iVar3 < 0) {
      *(undefined4 *)(param_1 + 0xf8) = 0;
    }
  }
  return;
}

