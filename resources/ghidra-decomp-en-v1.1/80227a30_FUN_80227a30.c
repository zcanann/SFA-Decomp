// Function: FUN_80227a30
// Entry: 80227a30
// Size: 596 bytes

void FUN_80227a30(uint param_1)

{
  char cVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  float *pfVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pfVar6 = *(float **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  cVar1 = *(char *)(pfVar6 + 1);
  if (cVar1 == '\x01') {
    iVar3 = FUN_8002ba84();
    uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x20));
    if (uVar4 == 0) {
      uVar4 = FUN_8013930c(iVar3);
      if ((uVar4 != param_1) || (iVar5 = FUN_8013929c(iVar3), iVar5 != 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
        *(undefined *)(pfVar6 + 1) = 0;
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      if ((iVar3 != 0) && ((*(byte *)(param_1 + 0xaf) & 4) != 0)) {
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,4);
      }
    }
    if (*(char *)((int)pfVar6 + 5) != '\0') {
      FUN_8000bb38(param_1,0x9f);
      FUN_8000bb38(param_1,0x9e);
      *(undefined *)(pfVar6 + 1) = 2;
      *pfVar6 = FLOAT_803e7a7c;
    }
  }
  else if (cVar1 == '\0') {
    uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x20));
    if (uVar4 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      *(undefined *)(pfVar6 + 1) = 1;
    }
  }
  else if (cVar1 == '\x02') {
    fVar2 = *pfVar6 + FLOAT_803dc074;
    *pfVar6 = fVar2;
    if (FLOAT_803e7a80 <= fVar2) {
      *(undefined *)(pfVar6 + 1) = 3;
    }
  }
  else if (cVar1 == '\x03') {
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x73a,0,2,0xffffffff,0);
    }
    if (*(int *)(param_1 + 0xf4) == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0x69);
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,1);
    }
  }
  *(undefined4 *)(param_1 + 0xf4) = 1;
  return;
}

