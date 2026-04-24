// Function: FUN_80148c18
// Entry: 80148c18
// Size: 372 bytes

void FUN_80148c18(int param_1,int param_2)

{
  *(undefined *)(param_2 + 0x2ef) = 1;
  if (((*(uint *)(param_2 + 0x2dc) & 0x1000) != 0) && ((*(uint *)(param_2 + 0x2e0) & 0x1000) == 0))
  {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    *(float *)(param_2 + 0x308) = FLOAT_803e256c / (FLOAT_803e2570 * *(float *)(param_2 + 0x314));
    *(undefined *)(param_2 + 0x323) = 1;
    FUN_80030334((double)FLOAT_803e2574,param_1,*(undefined *)(param_2 + 800),0x10);
    if (*(int *)(param_1 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 4;
    FUN_8000b4d0(param_1,1099,2);
    FUN_80035f20(param_1);
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) == 0) {
    *(char *)(param_1 + 0x36) = (char)(int)(FLOAT_803e257c * *(float *)(param_1 + 0x98));
    *(undefined4 *)(param_2 + 0x30c) = *(undefined4 *)(param_1 + 0x98);
  }
  else {
    *(float *)(param_2 + 0x308) = FLOAT_803e2578;
    *(undefined *)(param_2 + 0x323) = 0;
    FUN_80030334((double)FLOAT_803e2574,param_1,0,0);
    if (*(int *)(param_1 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xffffef7f;
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) & 0xfffffffb;
    *(float *)(param_2 + 0x30c) = FLOAT_803e2574;
    *(undefined *)(param_1 + 0x36) = 0xff;
  }
  return;
}

