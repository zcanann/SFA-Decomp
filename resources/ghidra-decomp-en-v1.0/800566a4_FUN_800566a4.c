// Function: FUN_800566a4
// Entry: 800566a4
// Size: 260 bytes

void FUN_800566a4(int param_1,uint param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = 0;
  iVar4 = 0x28;
  do {
    piVar1 = (int *)(DAT_803dce6c + iVar2);
    if (((*piVar1 == param_1) && (param_2 == *(byte *)((int)piVar1 + 0xe))) &&
       (0 < *(short *)(piVar1 + 3))) {
      *(short *)(piVar1 + 3) = *(short *)(piVar1 + 3) + -1;
      if (*(short *)(DAT_803dce6c + iVar2 + 0xc) == 0) {
        *(undefined4 *)(DAT_803dce6c + iVar2 + 4) = 0;
        *(undefined *)(DAT_803dce6c + iVar2 + 0xe) = 0;
        *(undefined4 *)(DAT_803dce6c + iVar2) = 0;
        *(undefined4 *)(DAT_803dce6c + iVar2 + 8) = 0;
      }
    }
    iVar3 = iVar2 + 0x10;
    piVar1 = (int *)(DAT_803dce6c + iVar3);
    if (((*piVar1 == param_1) && (param_2 == *(byte *)((int)piVar1 + 0xe))) &&
       (0 < *(short *)(piVar1 + 3))) {
      *(short *)(piVar1 + 3) = *(short *)(piVar1 + 3) + -1;
      if (*(short *)(DAT_803dce6c + iVar3 + 0xc) == 0) {
        *(undefined4 *)(DAT_803dce6c + iVar3 + 4) = 0;
        *(undefined *)(DAT_803dce6c + iVar2 + 0x1e) = 0;
        *(undefined4 *)(DAT_803dce6c + iVar3) = 0;
        *(undefined4 *)(DAT_803dce6c + iVar2 + 0x18) = 0;
      }
    }
    iVar2 = iVar2 + 0x20;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  return;
}

