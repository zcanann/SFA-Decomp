// Function: FUN_80057ea0
// Entry: 80057ea0
// Size: 776 bytes

void FUN_80057ea0(int param_1,int param_2,int *param_3,int *param_4,int *param_5,int *param_6,
                 int param_7,int param_8,int param_9)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  short *psVar5;
  short *psVar6;
  
  if (param_9 != -1) {
    psVar5 = (short *)(DAT_80382e9c + (short)(&DAT_80382eb0)[param_9 * 4] * 10);
    psVar6 = (short *)(&DAT_80382eac)[param_9 * 2];
    if (param_9 != -1) {
      if (param_8 == 0) {
        iVar2 = *(int *)(psVar6 + 10);
        iVar3 = *(int *)(psVar6 + 0x16);
      }
      else {
        iVar2 = *(int *)(psVar6 + 0x18);
        iVar3 = *(int *)(psVar6 + 0x1a);
      }
      uVar1 = (param_1 - *psVar5) + (param_2 - psVar5[2]) * (int)*psVar6;
      if (param_7 == 0) {
        uVar4 = *(uint *)(iVar2 + uVar1 * 8);
        *param_3 = (uVar4 >> 0xc & 0xf) - 7;
        param_3[2] = (uVar4 >> 8 & 0xf) - 7;
        param_3[1] = (uVar4 >> 4 & 0xf) - 7;
        param_3[3] = (uVar4 & 0xf) - 7;
        *param_4 = (uVar4 >> 0x1c) - 7;
        param_4[2] = (uVar4 >> 0x18 & 0xf) - 7;
        param_4[1] = (uVar4 >> 0x14 & 0xf) - 7;
        param_4[3] = (uVar4 >> 0x10 & 0xf) - 7;
        uVar1 = *(uint *)(iVar2 + uVar1 * 8 + 4);
        *param_5 = (uVar1 >> 0xc & 0xf) - 7;
        param_5[2] = (uVar1 >> 8 & 0xf) - 7;
        param_5[1] = (uVar1 >> 4 & 0xf) - 7;
        param_5[3] = (uVar1 & 0xf) - 7;
        *param_6 = (uVar1 >> 0x1c) - 7;
        param_6[2] = (uVar1 >> 0x18 & 0xf) - 7;
        param_6[1] = (uVar1 >> 0x14 & 0xf) - 7;
        param_6[3] = (uVar1 >> 0x10 & 0xf) - 7;
      }
      else {
        *param_3 = 0;
        param_3[1] = -1;
        param_3[2] = 0;
        param_3[3] = -1;
        *param_4 = 0;
        param_4[1] = -1;
        param_4[2] = 0;
        param_4[3] = -1;
        *param_5 = 0;
        param_5[1] = -1;
        param_5[2] = 0;
        param_5[3] = -1;
        *param_6 = 0;
        param_6[1] = -1;
        param_6[2] = 0;
        param_6[3] = -1;
        uVar1 = *(uint *)(*(int *)(psVar6 + 6) + ((int)(uVar1 * 2 | uVar1 >> 0x1f) >> 1) * 4) & 0x7f
        ;
        if (uVar1 != 0x7f) {
          uVar1 = *(uint *)(iVar3 + (param_7 + uVar1 * 4 + -1) * 4);
          *param_3 = (uVar1 >> 0xc & 0xf) - 7;
          param_3[2] = (uVar1 >> 8 & 0xf) - 7;
          param_3[1] = (uVar1 >> 4 & 0xf) - 7;
          param_3[3] = (uVar1 & 0xf) - 7;
          *param_4 = (uVar1 >> 0x1c) - 7;
          param_4[2] = (uVar1 >> 0x18 & 0xf) - 7;
          param_4[1] = (uVar1 >> 0x14 & 0xf) - 7;
          param_4[3] = (uVar1 >> 0x10 & 0xf) - 7;
        }
      }
    }
    else {
      *param_3 = -1;
      param_3[1] = 1;
      param_3[2] = -1;
      param_3[3] = 1;
      *param_4 = 0;
      param_4[1] = 0;
      param_4[2] = 0;
      param_4[3] = -1;
      *param_5 = 0;
      param_5[1] = 0;
      param_5[2] = 0;
      param_5[3] = -1;
      *param_6 = 0;
      param_6[1] = 0;
      param_6[2] = 0;
      param_6[3] = -1;
      if (param_7 != 0) {
        param_3[3] = -2;
      }
    }
  }
  else {
    *param_3 = -1;
    param_3[1] = 1;
    param_3[2] = -1;
    param_3[3] = 1;
    *param_4 = 0;
    param_4[1] = 0;
    param_4[2] = 0;
    param_4[3] = -1;
    *param_5 = 0;
    param_5[1] = 0;
    param_5[2] = 0;
    param_5[3] = -1;
    *param_6 = 0;
    param_6[1] = 0;
    param_6[2] = 0;
    param_6[3] = -1;
    if (param_7 != 0) {
      param_3[3] = -2;
    }
  }
  return;
}

