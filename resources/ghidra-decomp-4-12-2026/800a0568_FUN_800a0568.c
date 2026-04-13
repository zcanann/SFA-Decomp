// Function: FUN_800a0568
// Entry: 800a0568
// Size: 412 bytes

void FUN_800a0568(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  
  fVar2 = FLOAT_803e00b8 * *(float *)(param_2 + 4) * FLOAT_803ddf04;
  fVar3 = FLOAT_803e00b8 * *(float *)(param_2 + 8) * FLOAT_803ddf04;
  iVar5 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar6 = *(int *)(param_1 + (1 - (uint)*(byte *)(param_1 + 0x130)) * 4 + 0x78);
  uVar7 = 0;
  uVar8 = 0;
  for (iVar4 = 0; iVar4 < *(short *)(param_1 + 0xea); iVar4 = iVar4 + 1) {
    *(undefined2 *)(iVar5 + 8) = *(undefined2 *)(iVar6 + 8);
    *(undefined2 *)(iVar5 + 10) = *(undefined2 *)(iVar6 + 10);
    *(short *)(iVar5 + 8) = *(short *)(iVar5 + 8) + (short)(int)fVar2;
    if (0x100 < *(short *)(iVar5 + 8)) {
      uVar7 = uVar7 + 1 & 0xff;
    }
    if (*(short *)(iVar5 + 8) < -0x100) {
      uVar7 = uVar7 + 1 & 0xff;
    }
    *(short *)(iVar5 + 10) = *(short *)(iVar5 + 10) + (short)(int)fVar3;
    if (0x100 < *(short *)(iVar5 + 10)) {
      uVar8 = uVar8 + 1 & 0xff;
    }
    if (*(short *)(iVar5 + 10) < -0x100) {
      uVar8 = uVar8 + 1 & 0xff;
    }
    iVar5 = iVar5 + 0x10;
    iVar6 = iVar6 + 0x10;
  }
  iVar4 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  for (iVar5 = 0; iVar5 < *(short *)(param_1 + 0xea); iVar5 = iVar5 + 1) {
    if (uVar7 == (int)*(short *)(param_1 + 0xea)) {
      sVar1 = *(short *)(iVar4 + 8);
      if (sVar1 < 0x101) {
        *(short *)(iVar4 + 8) = sVar1 + 0x100;
      }
      else {
        *(short *)(iVar4 + 8) = sVar1 + -0x100;
      }
    }
    if (uVar8 == (int)*(short *)(param_1 + 0xea)) {
      sVar1 = *(short *)(iVar4 + 10);
      if (sVar1 < 0x101) {
        *(short *)(iVar4 + 10) = sVar1 + 0x100;
      }
      else {
        *(short *)(iVar4 + 10) = sVar1 + -0x100;
      }
    }
    iVar4 = iVar4 + 0x10;
  }
  return;
}

