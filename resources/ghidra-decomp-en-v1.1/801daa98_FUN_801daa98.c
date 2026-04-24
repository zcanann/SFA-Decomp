// Function: FUN_801daa98
// Entry: 801daa98
// Size: 352 bytes

void FUN_801daa98(int param_1,undefined *param_2,int param_3)

{
  int iVar1;
  undefined *puVar2;
  int iVar3;
  
  iVar1 = FUN_8002bac4();
  FUN_80035ff8(param_1);
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (param_3 != 0) {
    FUN_80296454(iVar1,1);
    FUN_80296e8c(iVar1,1);
    iVar1 = 2;
    puVar2 = param_2;
    do {
      iVar3 = *(int *)(puVar2 + 0x38);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x38) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x3c);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x3c) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x40);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x40) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x44);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x44) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x48);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x48) = 0;
      }
      puVar2 = puVar2 + 0x14;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  *param_2 = 6;
  return;
}

