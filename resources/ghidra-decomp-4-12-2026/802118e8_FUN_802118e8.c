// Function: FUN_802118e8
// Entry: 802118e8
// Size: 204 bytes

void FUN_802118e8(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  
  iVar1 = FUN_8028683c();
  piVar4 = *(int **)(iVar1 + 0xb8);
  if (*(int *)(iVar1 + 0xc4) != 0) {
    *piVar4 = *(int *)(iVar1 + 0xc4);
    *(undefined4 *)(iVar1 + 0xc4) = 0;
  }
  uVar2 = FUN_800803dc((float *)(piVar4 + 5));
  if ((uVar2 == 0) &&
     (iVar3 = FUN_8005b478((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10)),
     iVar3 != -1)) {
    iVar3 = piVar4[1];
    if ((iVar3 != 0) && ((*(char *)(iVar3 + 0x2f8) != '\0' && (*(char *)(iVar3 + 0x4c) != '\0')))) {
      FUN_80060630(iVar3);
    }
    FUN_8003b9ec(iVar1);
  }
  FUN_80286888();
  return;
}

