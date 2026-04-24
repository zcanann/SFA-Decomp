// Function: FUN_80028e34
// Entry: 80028e34
// Size: 336 bytes

void FUN_80028e34(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_1 + 0xf8); iVar2 = iVar2 + 1) {
    iVar3 = *(int *)(param_1 + 0x38) + iVar1;
    iVar4 = iVar3;
    for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar3 + 0x41); iVar5 = iVar5 + 1) {
      if (*(int *)(iVar4 + 0x24) == -1) {
        *(undefined4 *)(iVar4 + 0x24) = 0;
      }
      else {
        *(undefined4 *)(iVar4 + 0x24) =
             *(undefined4 *)(*(int *)(param_1 + 0x20) + *(int *)(iVar4 + 0x24) * 4);
      }
      iVar4 = iVar4 + 8;
    }
    if (*(int *)(iVar3 + 0x34) == -1) {
      *(undefined4 *)(iVar3 + 0x34) = 0;
    }
    else {
      *(undefined4 *)(iVar3 + 0x34) =
           *(undefined4 *)(*(int *)(param_1 + 0x20) + *(int *)(iVar3 + 0x34) * 4);
    }
    if (*(int *)(iVar3 + 0x38) == -1) {
      *(undefined4 *)(iVar3 + 0x38) = 0;
    }
    else {
      *(undefined4 *)(iVar3 + 0x38) =
           *(undefined4 *)(*(int *)(param_1 + 0x20) + *(int *)(iVar3 + 0x38) * 4);
    }
    if (*(int *)(iVar3 + 0x1c) == -1) {
      *(undefined4 *)(iVar3 + 0x1c) = 0;
    }
    else if (*(int *)(iVar3 + 0x1c) == -2) {
      *(undefined4 *)(iVar3 + 0x1c) = 0;
    }
    else {
      *(undefined4 *)(iVar3 + 0x1c) = 1;
    }
    if (*(int *)(iVar3 + 0x18) == -1) {
      *(undefined4 *)(iVar3 + 0x18) = 0;
    }
    else {
      *(undefined4 *)(iVar3 + 0x18) =
           *(undefined4 *)(*(int *)(param_1 + 0x20) + *(int *)(iVar3 + 0x18) * 4);
    }
    if ((*(ushort *)(param_1 + 0xe2) & 0xc) == 0) {
      *(undefined4 *)(iVar3 + 8) = 0;
    }
    if ((*(ushort *)(param_1 + 0xe2) & 0xe00) == 0) {
      *(undefined4 *)(iVar3 + 0x14) = 0;
    }
    iVar1 = iVar1 + 0x44;
  }
  return;
}

