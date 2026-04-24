// Function: FUN_8014bc98
// Entry: 8014bc98
// Size: 388 bytes

void FUN_8014bc98(short *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  float local_28;
  float local_24;
  float local_20;
  
  iVar2 = *(int *)(param_2 + 0x29c);
  if (iVar2 != 0) {
    if ((*(uint *)(param_2 + 0x2e4) & 0x8000) == 0) {
      local_28 = *(float *)(param_1 + 0xc) - *(float *)(iVar2 + 0x18);
      local_24 = *(float *)(param_1 + 0xe) - *(float *)(iVar2 + 0x1c);
      local_20 = *(float *)(param_1 + 0x10) - *(float *)(iVar2 + 0x20);
    }
    else {
      local_28 = *(float *)(param_1 + 0xc) - *(float *)(iVar2 + 0x18);
      local_24 = FLOAT_803e2574;
      local_20 = *(float *)(param_1 + 0x10) - *(float *)(iVar2 + 0x20);
    }
    uVar3 = FUN_800217c0(-(double)local_28,-(double)local_20);
    if (*(short **)(param_1 + 0x18) == (short *)0x0) {
      sVar1 = *param_1;
    }
    else {
      sVar1 = *param_1 + **(short **)(param_1 + 0x18);
    }
    uVar3 = (uVar3 & 0xffff) - ((int)sVar1 & 0xffffU);
    if (0x8000 < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    if ((int)uVar3 < -0x8000) {
      uVar3 = uVar3 + 0xffff;
    }
    *(short *)(param_2 + 0x2a2) = (short)(uVar3 & 0xffff);
    *(short *)(param_2 + 0x2a0) = (short)((uVar3 & 0xffff) >> 0xd);
    dVar4 = (double)FUN_802931a0((double)(local_20 * local_20 +
                                         local_28 * local_28 + local_24 * local_24));
    *(short *)(param_2 + 0x2a4) = (short)(int)dVar4;
    *(short *)(param_2 + 0x2a6) =
         (short)(int)(*(float *)(*(int *)(param_2 + 0x29c) + 0x1c) - *(float *)(param_1 + 0xe));
  }
  return;
}

