// Function: FUN_80028ec0
// Entry: 80028ec0
// Size: 212 bytes

void FUN_80028ec0(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  *(undefined4 *)(param_1 + 0x94) = *(undefined4 *)(param_1 + 0xa4);
  iVar2 = 0;
  iVar3 = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(ushort *)(param_1 + 0x8a); iVar4 = iVar4 + 1) {
    *(undefined4 *)(*(int *)(param_2 + 0x40) + iVar3) =
         *(undefined4 *)(*(int *)(param_1 + 0xa4) + iVar2 + 0x60);
    uVar1 = *(uint *)(*(int *)(param_1 + 0xa4) + iVar2 + 100);
    if (uVar1 < *(uint *)(param_1 + 0xa8)) {
      *(uint *)(*(int *)(param_1 + 0xa4) + iVar2 + 100) = *(uint *)(param_1 + 0xa8) + uVar1;
    }
    iVar2 = iVar2 + 0x74;
    iVar3 = iVar3 + 4;
  }
  *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(param_1 + 200);
  iVar2 = 0;
  iVar3 = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(ushort *)(param_1 + 0xae); iVar4 = iVar4 + 1) {
    *(int *)(*(int *)(param_2 + 0x44) + iVar3) =
         *(int *)(param_2 + 0x24) + *(int *)(*(int *)(param_1 + 200) + iVar2 + 0x60);
    uVar1 = *(uint *)(*(int *)(param_1 + 200) + iVar2 + 100);
    if (uVar1 < *(uint *)(param_1 + 0xcc)) {
      *(uint *)(*(int *)(param_1 + 200) + iVar2 + 100) = *(uint *)(param_1 + 0xcc) + uVar1;
    }
    iVar2 = iVar2 + 0x74;
    iVar3 = iVar3 + 4;
  }
  return;
}

