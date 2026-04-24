// Function: FUN_801b9cfc
// Entry: 801b9cfc
// Size: 284 bytes

void FUN_801b9cfc(int param_1)

{
  float fVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_800394ac(param_1,0,0);
  if (iVar3 != 0) {
    if (*(short *)(param_1 + 0x46) == 0xd1) {
      uVar2 = (undefined)(int)FLOAT_803e4b9c;
      *(undefined *)(iVar3 + 0xc) = uVar2;
      *(undefined *)(iVar3 + 0xd) = uVar2;
      *(undefined *)(iVar3 + 0xe) = uVar2;
    }
    else {
      uVar2 = (undefined)(int)FLOAT_803e4b9c;
      *(undefined *)(iVar3 + 0xc) = uVar2;
      *(undefined *)(iVar3 + 0xd) = uVar2;
      *(undefined *)(iVar3 + 0xe) = uVar2;
    }
  }
  iVar3 = FUN_8002b9ec();
  dVar5 = (double)FUN_800216d0(iVar3 + 0x18,param_1 + 0x18);
  if (dVar5 < (double)FLOAT_803e4ba0) {
    fVar1 = *(float *)(iVar4 + 0x24) - FLOAT_803db414;
    *(float *)(iVar4 + 0x24) = fVar1;
    if (fVar1 < FLOAT_803e4b9c) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x20d,0,2,0xffffffff,0);
      *(float *)(iVar4 + 0x24) = FLOAT_803e4ba4;
    }
  }
  return;
}

