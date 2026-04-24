// Function: FUN_801fb23c
// Entry: 801fb23c
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x801fb410) */

void FUN_801fb23c(int param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 in_f31;
  double dVar6;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(param_1 + 0xb8);
  dVar6 = (double)FLOAT_803e60e0;
  if (*(short *)(param_1 + 0x46) == 0x53f) {
    dVar6 = (double)FLOAT_803e60e4;
  }
  else if (*(short *)(param_1 + 0x46) == 0x3bf) {
    dVar6 = (double)FLOAT_803e60e8;
  }
  if (*(char *)(iVar3 + 0x1c) < '\0') {
    *(float *)(param_1 + 0x10) = (float)((double)*(float *)(iVar4 + 0xc) + dVar6);
    *(byte *)(iVar3 + 0x1c) = *(byte *)(iVar3 + 0x1c) & 0x7f;
  }
  sVar1 = *(short *)(iVar3 + 10);
  if (((sVar1 == 4) || (3 < sVar1)) || (sVar1 < 3)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      iVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0xe));
      if (iVar2 == 0) {
        *(undefined2 *)(iVar3 + 10) = 3;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      }
    }
    else {
      FUN_80014b3c(0,0x100);
      (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      *(undefined2 *)(iVar3 + 10) = 3;
      FUN_8000bb18(param_1,0x113);
      FUN_8000b7bc(param_1,8);
      FUN_800200e8((int)*(short *)(iVar3 + 0xe),0);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      iVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0xe));
      if (iVar2 != 0) {
        *(undefined2 *)(iVar3 + 10) = 4;
        *(float *)(param_1 + 0x10) = (float)((double)*(float *)(iVar4 + 0xc) + dVar6);
      }
    }
    else {
      FUN_80014b3c(0,0x100);
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      *(undefined2 *)(iVar3 + 10) = 4;
      FUN_8000bb18(param_1,0x113);
      FUN_8000b7bc(param_1,8);
      FUN_800200e8((int)*(short *)(iVar3 + 0xe),1);
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

