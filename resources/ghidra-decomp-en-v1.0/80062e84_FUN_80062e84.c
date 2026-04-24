// Function: FUN_80062e84
// Entry: 80062e84
// Size: 596 bytes

void FUN_80062e84(short *param_1,short *param_2,int param_3)

{
  int iVar1;
  short *psVar2;
  int iVar3;
  float local_28;
  float local_24;
  undefined auStack32 [16];
  
  psVar2 = *(short **)(param_1 + 0x18);
  if (psVar2 != param_2) {
    if (psVar2 != (short *)0x0) {
      FUN_8000e318(psVar2);
    }
    if (param_2 != (short *)0x0) {
      FUN_8000e318(param_2);
    }
    if (param_1[0x22] == 1) {
      FUN_80296eb4(param_1,param_2);
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
        FUN_8000e0a0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),param_1 + 0xc,param_1 + 0xe,param_1 + 0x10,
                     psVar2);
        FUN_8000e0a0((double)*(float *)(param_1 + 0x40),(double)*(float *)(param_1 + 0x42),
                     (double)*(float *)(param_1 + 0x44),param_1 + 0x46,param_1 + 0x48,param_1 + 0x4a
                     ,psVar2);
        FUN_8000df1c((double)*(float *)(param_1 + 0x12),(double)FLOAT_803decb4,
                     (double)*(float *)(param_1 + 0x16),&local_24,auStack32,&local_28,psVar2);
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
          FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                       (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10);
          FUN_8000e034((double)*(float *)(param_1 + 0x46),(double)*(float *)(param_1 + 0x48),
                       (double)*(float *)(param_1 + 0x4a),param_1 + 0x40,param_1 + 0x42,
                       param_1 + 0x44,*(undefined4 *)(param_1 + 0x18));
          FUN_8000dfa8((double)local_24,(double)FLOAT_803decb4,(double)local_28,param_1 + 0x12,
                       auStack32,param_1 + 0x16,*(undefined4 *)(param_1 + 0x18));
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

