// Function: FUN_80180338
// Entry: 80180338
// Size: 380 bytes

void FUN_80180338(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_8002b9ac();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (iVar2 != 0) {
    iVar3 = FUN_80138f84();
    uVar1 = countLeadingZeros(param_1 - iVar3);
    if ((uVar1 >> 5 == 0) && (*(short *)(iVar4 + 0x1e) != -1)) {
      FUN_800200e8((int)*(short *)(iVar4 + 0x1e),0);
    }
    if ((*(short *)(iVar4 + 0x20) == -1) || (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
      if ((uVar1 >> 5 == 0) ||
         (dVar5 = (double)FUN_800216d0(param_1 + 0x18,iVar2 + 0x18), (double)FLOAT_803e38a8 <= dVar5
         )) {
        iVar4 = FUN_8012ebc8();
        if (iVar4 == -1) {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0;
        }
        else {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0x10;
        }
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) &&
           (*(int *)(param_1 + 0x74) != 0)) {
          FUN_80041018(param_1);
        }
        if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,3);
        }
      }
      else if (*(short *)(iVar4 + 0x1e) != -1) {
        FUN_800200e8((int)*(short *)(iVar4 + 0x1e),1);
      }
    }
  }
  return;
}

