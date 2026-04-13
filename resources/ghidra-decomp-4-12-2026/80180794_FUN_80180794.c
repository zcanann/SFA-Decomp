// Function: FUN_80180794
// Entry: 80180794
// Size: 216 bytes

void FUN_80180794(int param_1)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a);
  if ((((uVar1 == 0xffffffff) || (uVar1 = FUN_80020078(uVar1), uVar1 != 0)) &&
      (iVar2 = FUN_8002ba84(), iVar2 != 0)) &&
     (cVar3 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x44))(), cVar3 == '\0')) {
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,3);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80041110();
  }
  return;
}

