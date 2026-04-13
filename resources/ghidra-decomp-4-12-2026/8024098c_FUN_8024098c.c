// Function: FUN_8024098c
// Entry: 8024098c
// Size: 180 bytes

void FUN_8024098c(int param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (*piVar2 == 0) {
    iVar1 = FUN_8002e1ac(0x47dd9);
    *piVar2 = iVar1;
  }
  if (*piVar2 != 0) {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*piVar2 + 0xc);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*piVar2 + 0x10);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*piVar2 + 0x14);
  }
  *(undefined *)((int)piVar2 + 0xd) = *(undefined *)(piVar2 + 3);
  if (*(char *)(piVar2 + 3) == '\x01') {
    FUN_80240708(param_1,(int)piVar2);
  }
  return;
}

