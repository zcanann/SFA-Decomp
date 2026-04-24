// Function: FUN_801da4a8
// Entry: 801da4a8
// Size: 352 bytes

void FUN_801da4a8(int param_1,undefined *param_2,int param_3)

{
  undefined4 uVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  
  uVar1 = FUN_8002b9ec();
  FUN_80035f00(param_1);
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (param_3 != 0) {
    FUN_80295cf4(uVar1,1);
    FUN_8029672c(uVar1,1);
    iVar4 = 2;
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
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  *param_2 = 6;
  return;
}

