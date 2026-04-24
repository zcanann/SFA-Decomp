// Function: FUN_80180890
// Entry: 80180890
// Size: 380 bytes

void FUN_80180890(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_8002ba84();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (iVar2 != 0) {
    iVar3 = FUN_8013930c(iVar2);
    uVar1 = countLeadingZeros(param_1 - iVar3);
    if ((uVar1 >> 5 == 0) && ((int)*(short *)(iVar5 + 0x1e) != 0xffffffff)) {
      FUN_800201ac((int)*(short *)(iVar5 + 0x1e),0);
    }
    if (((int)*(short *)(iVar5 + 0x20) == 0xffffffff) ||
       (uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x20)), uVar4 != 0)) {
      if ((uVar1 >> 5 == 0) ||
         (dVar6 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18)),
         (double)FLOAT_803e4540 <= dVar6)) {
        iVar5 = FUN_8012f000();
        if (iVar5 == -1) {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0;
        }
        else {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0x10;
        }
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) &&
           (*(int *)(param_1 + 0x74) != 0)) {
          FUN_80041110();
        }
        if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,3);
        }
      }
      else if ((int)*(short *)(iVar5 + 0x1e) != 0xffffffff) {
        FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
      }
    }
  }
  return;
}

