// Function: FUN_8016f7f4
// Entry: 8016f7f4
// Size: 320 bytes

void FUN_8016f7f4(int param_1)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  if (((*(short *)(param_1 + 0x46) != 0x83e) && ((*(byte *)(piVar3 + 0x1c) & 8) == 0)) &&
     (iVar2 = *(int *)(*(int *)(param_1 + 0x54) + 0x50), iVar2 != 0)) {
    if (*(short *)(iVar2 + 0x46) == 0x6e8) {
      cVar1 = FUN_80236b10(iVar2);
      if (cVar1 != -1) {
        *(char *)((int)piVar3 + 0x71) = cVar1;
        if (*piVar3 != 0) {
          iVar2 = (uint)*(byte *)((int)piVar3 + 0x71) * 3;
          FUN_8001daf0(*piVar3,(&DAT_80320978)[iVar2],(&DAT_80320979)[iVar2],(&DAT_8032097a)[iVar2],
                       0);
        }
      }
      FUN_80035f20(param_1);
    }
    else {
      piVar3[0xe] = (int)FLOAT_803e3358;
      if (*(char *)((int)piVar3 + 0x71) == '\0') {
        FUN_80099660((double)FLOAT_803e3354,param_1,3);
      }
      else if (*(char *)((int)piVar3 + 0x71) == '\x01') {
        FUN_80099660((double)FLOAT_803e3354,param_1,0);
      }
      else {
        FUN_80099660((double)FLOAT_803e3354,param_1,6);
      }
      *(undefined *)(param_1 + 0x36) = 0;
      if (*piVar3 != 0) {
        FUN_8001f384();
        *piVar3 = 0;
      }
    }
    FUN_80036fa4(param_1,2);
  }
  return;
}

