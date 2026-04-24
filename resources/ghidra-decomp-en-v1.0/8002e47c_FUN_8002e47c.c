// Function: FUN_8002e47c
// Entry: 8002e47c
// Size: 428 bytes

void FUN_8002e47c(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  
  FUN_802860d0();
  iVar9 = 0;
  for (iVar7 = 0; iVar7 < DAT_803dcb84; iVar7 = iVar7 + 1) {
    iVar5 = *(int *)(DAT_803dcb88 + iVar9);
    if ((iVar5 != 0) && (*(int *)(iVar5 + 0x50) != 0)) {
      if (*(int *)(iVar5 + 100) != 0) {
        *(undefined4 *)(*(int *)(iVar5 + 100) + 0xc) = 0;
      }
      iVar3 = 0;
      for (iVar6 = 0; iVar6 < *(char *)(*(int *)(iVar5 + 0x50) + 0x55); iVar6 = iVar6 + 1) {
        piVar1 = *(int **)(*(int *)(iVar5 + 0x7c) + iVar3);
        if ((piVar1 != (int *)0x0) &&
           (*(ushort *)(piVar1 + 6) = *(ushort *)(piVar1 + 6) & 0xfff7,
           *(char *)(*piVar1 + 0xf9) != '\0')) {
          FUN_80027814((double)FLOAT_803db414);
        }
        iVar3 = iVar3 + 4;
      }
      iVar3 = iVar5;
      for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar5 + 0xeb); iVar6 = iVar6 + 1) {
        iVar4 = *(int *)(iVar3 + 200);
        if ((iVar4 != 0) && (*(int *)(iVar4 + 0x50) != 0)) {
          iVar10 = 0;
          for (iVar8 = 0; iVar8 < *(char *)(*(int *)(iVar4 + 0x50) + 0x55); iVar8 = iVar8 + 1) {
            piVar1 = *(int **)(*(int *)(iVar4 + 0x7c) + iVar10);
            if (((piVar1 != (int *)0x0) &&
                (*(ushort *)(piVar1 + 6) = *(ushort *)(piVar1 + 6) & 0xfff7,
                *(char *)(*piVar1 + 0xf9) != '\0')) &&
               ((*(int *)(iVar4 + 0xc0) == 0 ||
                ((iVar2 = *(int *)(*(int *)(iVar4 + 0xc0) + 0xb8), iVar2 != 0 &&
                 (*(char *)(iVar2 + 0x56) == '\0')))))) {
              FUN_80027814((double)FLOAT_803db414);
            }
            iVar10 = iVar10 + 4;
          }
        }
        iVar3 = iVar3 + 4;
      }
    }
    iVar9 = iVar9 + 4;
  }
  FUN_8028611c();
  return;
}

