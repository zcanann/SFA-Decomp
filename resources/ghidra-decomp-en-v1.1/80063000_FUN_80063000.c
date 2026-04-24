// Function: FUN_80063000
// Entry: 80063000
// Size: 596 bytes

void FUN_80063000(short *param_1,short *param_2,int param_3)

{
  int iVar1;
  short *psVar2;
  int iVar3;
  float local_28;
  float local_24;
  float afStack_20 [4];
  
  psVar2 = *(short **)(param_1 + 0x18);
  if (psVar2 != param_2) {
    if (psVar2 != (short *)0x0) {
      FUN_8000e338();
    }
    if (param_2 != (short *)0x0) {
      FUN_8000e338();
    }
    if (param_1[0x22] == 1) {
      FUN_80297614();
    }
    else {
      *(short **)(param_1 + 0x18) = param_2;
      iVar1 = *(int *)(param_1 + 0x2a);
      if (psVar2 == (short *)0x0) {
        local_24 = *(float *)(param_1 + 0x12);
        local_28 = *(float *)(param_1 + 0x16);
        iVar3 = (int)*param_1;
      }
      else {
        FUN_8000e0c0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),(float *)(param_1 + 0xc),
                     (float *)(param_1 + 0xe),(float *)(param_1 + 0x10),(int)psVar2);
        FUN_8000e0c0((double)*(float *)(param_1 + 0x40),(double)*(float *)(param_1 + 0x42),
                     (double)*(float *)(param_1 + 0x44),(float *)(param_1 + 0x46),
                     (float *)(param_1 + 0x48),(float *)(param_1 + 0x4a),(int)psVar2);
        FUN_8000df3c((double)*(float *)(param_1 + 0x12),(double)FLOAT_803df934,
                     (double)*(float *)(param_1 + 0x16),&local_24,afStack_20,&local_28,(int)psVar2);
        iVar3 = (int)*psVar2 + (int)*param_1;
      }
      if (param_3 != 0) {
        if (*(int *)(param_1 + 0x18) == 0) {
          *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_1 + 0xc);
          *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_1 + 0xe);
          *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_1 + 0x10);
          *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 0x46);
          *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 0x48);
          *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 0x4a);
          *(float *)(param_1 + 0x12) = local_24;
          *(float *)(param_1 + 0x16) = local_28;
          *param_1 = (short)iVar3;
        }
        else {
          FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                       (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),
                       (float *)(param_1 + 8),(float *)(param_1 + 10),*(int *)(param_1 + 0x18));
          FUN_8000e054((double)*(float *)(param_1 + 0x46),(double)*(float *)(param_1 + 0x48),
                       (double)*(float *)(param_1 + 0x4a),(float *)(param_1 + 0x40),
                       (float *)(param_1 + 0x42),(float *)(param_1 + 0x44),*(int *)(param_1 + 0x18))
          ;
          FUN_8000dfc8((double)local_24,(double)FLOAT_803df934,(double)local_28,
                       (float *)(param_1 + 0x12),afStack_20,(float *)(param_1 + 0x16),
                       *(int *)(param_1 + 0x18));
          iVar3 = iVar3 - **(short **)(param_1 + 0x18);
          if (0x8000 < iVar3) {
            iVar3 = iVar3 + -0xffff;
          }
          if (iVar3 < -0x8000) {
            iVar3 = iVar3 + 0xffff;
          }
          *param_1 = (short)iVar3;
        }
      }
      if (iVar1 != 0) {
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_1 + 10);
        *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(param_1 + 0xe);
        *(undefined4 *)(iVar1 + 0x24) = *(undefined4 *)(param_1 + 0x10);
      }
    }
  }
  return;
}

