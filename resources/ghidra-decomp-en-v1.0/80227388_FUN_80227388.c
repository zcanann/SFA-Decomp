// Function: FUN_80227388
// Entry: 80227388
// Size: 596 bytes

void FUN_80227388(int param_1)

{
  char cVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pfVar5 = *(float **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  cVar1 = *(char *)(pfVar5 + 1);
  if (cVar1 == '\x01') {
    iVar3 = FUN_8002b9ac();
    iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20));
    if (iVar4 == 0) {
      iVar4 = FUN_80138f84(iVar3);
      if ((iVar4 != param_1) || (iVar4 = FUN_80138f14(iVar3), iVar4 != 0)) {
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        *(undefined *)(pfVar5 + 1) = 0;
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      if ((iVar3 != 0) && ((*(byte *)(param_1 + 0xaf) & 4) != 0)) {
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,4);
      }
    }
    if (*(char *)((int)pfVar5 + 5) != '\0') {
      FUN_8000bb18(param_1,0x9f);
      FUN_8000bb18(param_1,0x9e);
      *(undefined *)(pfVar5 + 1) = 2;
      *pfVar5 = FLOAT_803e6de4;
    }
  }
  else if (cVar1 == '\0') {
    iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20));
    if (iVar4 != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      *(undefined *)(pfVar5 + 1) = 1;
    }
  }
  else if (cVar1 == '\x02') {
    fVar2 = *pfVar5 + FLOAT_803db414;
    *pfVar5 = fVar2;
    if (FLOAT_803e6de8 <= fVar2) {
      *(undefined *)(pfVar5 + 1) = 3;
    }
  }
  else if (cVar1 == '\x03') {
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x73a,0,2,0xffffffff,0);
    }
    if (*(int *)(param_1 + 0xf4) == 0) {
      (**(code **)(*DAT_803dca54 + 0x54))(param_1,0x69);
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,1);
    }
  }
  *(undefined4 *)(param_1 + 0xf4) = 1;
  return;
}

