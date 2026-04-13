// Function: FUN_801ba2b0
// Entry: 801ba2b0
// Size: 284 bytes

void FUN_801ba2b0(int param_1)

{
  float fVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_800395a4(param_1,0);
  if (iVar3 != 0) {
    if (*(short *)(param_1 + 0x46) == 0xd1) {
      uVar2 = (undefined)(int)FLOAT_803e5834;
      *(undefined *)(iVar3 + 0xc) = uVar2;
      *(undefined *)(iVar3 + 0xd) = uVar2;
      *(undefined *)(iVar3 + 0xe) = uVar2;
    }
    else {
      uVar2 = (undefined)(int)FLOAT_803e5834;
      *(undefined *)(iVar3 + 0xc) = uVar2;
      *(undefined *)(iVar3 + 0xd) = uVar2;
      *(undefined *)(iVar3 + 0xe) = uVar2;
    }
  }
  iVar3 = FUN_8002bac4();
  dVar5 = FUN_80021794((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18));
  if (dVar5 < (double)FLOAT_803e5838) {
    fVar1 = *(float *)(iVar4 + 0x24) - FLOAT_803dc074;
    *(float *)(iVar4 + 0x24) = fVar1;
    if (fVar1 < FLOAT_803e5834) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x20d,0,2,0xffffffff,0);
      *(float *)(iVar4 + 0x24) = FLOAT_803e583c;
    }
  }
  return;
}

