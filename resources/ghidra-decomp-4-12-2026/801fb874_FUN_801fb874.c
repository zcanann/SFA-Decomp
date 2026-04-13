// Function: FUN_801fb874
// Entry: 801fb874
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x801fba48) */
/* WARNING: Removing unreachable block (ram,0x801fb884) */

void FUN_801fb874(uint param_1)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(param_1 + 0xb8);
  dVar5 = (double)FLOAT_803e6d78;
  if (*(short *)(param_1 + 0x46) == 0x53f) {
    dVar5 = (double)FLOAT_803e6d7c;
  }
  else if (*(short *)(param_1 + 0x46) == 0x3bf) {
    dVar5 = (double)FLOAT_803e6d80;
  }
  if (*(char *)(iVar3 + 0x1c) < '\0') {
    *(float *)(param_1 + 0x10) = (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    *(byte *)(iVar3 + 0x1c) = *(byte *)(iVar3 + 0x1c) & 0x7f;
  }
  sVar1 = *(short *)(iVar3 + 10);
  if (((sVar1 == 4) || (3 < sVar1)) || (sVar1 < 3)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xe));
      if (uVar2 == 0) {
        *(undefined2 *)(iVar3 + 10) = 3;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      }
    }
    else {
      FUN_80014b68(0,0x100);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
      *(undefined2 *)(iVar3 + 10) = 3;
      FUN_8000bb38(param_1,0x113);
      FUN_8000b7dc(param_1,8);
      FUN_800201ac((int)*(short *)(iVar3 + 0xe),0);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xe));
      if (uVar2 != 0) {
        *(undefined2 *)(iVar3 + 10) = 4;
        *(float *)(param_1 + 0x10) = (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
      }
    }
    else {
      FUN_80014b68(0,0x100);
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      *(undefined2 *)(iVar3 + 10) = 4;
      FUN_8000bb38(param_1,0x113);
      FUN_8000b7dc(param_1,8);
      FUN_800201ac((int)*(short *)(iVar3 + 0xe),1);
    }
  }
  return;
}

