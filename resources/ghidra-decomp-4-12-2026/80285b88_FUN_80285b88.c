// Function: FUN_80285b88
// Entry: 80285b88
// Size: 664 bytes

undefined4 FUN_80285b88(byte *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  uint uVar5;
  
  if (param_3 != 0) {
    iVar2 = 0;
    uVar3 = 0;
    if (0 < param_2) {
      if ((8 < param_2) && (uVar5 = param_2 - 1U >> 3, pbVar4 = param_1, 0 < param_2 + -8)) {
        do {
          uVar3 = uVar3 | (uint)*pbVar4 << (3 - iVar2) * 8 |
                  (uint)pbVar4[1] << (3 - (iVar2 + 1)) * 8 |
                  (uint)pbVar4[2] << (3 - (iVar2 + 2)) * 8 | (uint)pbVar4[3] << iVar2 * -8 |
                  (uint)pbVar4[4] << (3 - (iVar2 + 4)) * 8 |
                  (uint)pbVar4[5] << (3 - (iVar2 + 5)) * 8 |
                  (uint)pbVar4[6] << (3 - (iVar2 + 6)) * 8 |
                  (uint)pbVar4[7] << (3 - (iVar2 + 7)) * 8;
          pbVar4 = pbVar4 + 8;
          iVar2 = iVar2 + 8;
          uVar5 = uVar5 - 1;
        } while (uVar5 != 0);
      }
      pbVar4 = param_1 + iVar2;
      iVar1 = param_2 - iVar2;
      if (iVar2 < param_2) {
        do {
          uVar3 = uVar3 | (uint)*pbVar4 << (3 - iVar2) * 8;
          pbVar4 = pbVar4 + 1;
          iVar2 = iVar2 + 1;
          iVar1 = iVar1 + -1;
        } while (iVar1 != 0);
      }
    }
    DAT_cc006838 = uVar3;
  }
  DAT_cc006834 = param_3 << 2 | 1U | (param_2 + -1) * 0x10;
  do {
    uVar3 = DAT_cc006834;
  } while ((uVar3 & 1) != 0);
  if (param_3 == 0) {
    iVar2 = 0;
    uVar3 = DAT_cc006838;
    if (0 < param_2) {
      if ((8 < param_2) && (uVar5 = param_2 - 1U >> 3, 0 < param_2 + -8)) {
        do {
          *param_1 = (byte)(uVar3 >> (3 - iVar2) * 8);
          param_1[1] = (byte)(uVar3 >> (3 - (iVar2 + 1)) * 8);
          param_1[2] = (byte)(uVar3 >> (3 - (iVar2 + 2)) * 8);
          param_1[3] = (byte)(uVar3 >> iVar2 * -8);
          param_1[4] = (byte)(uVar3 >> (3 - (iVar2 + 4)) * 8);
          param_1[5] = (byte)(uVar3 >> (3 - (iVar2 + 5)) * 8);
          param_1[6] = (byte)(uVar3 >> (3 - (iVar2 + 6)) * 8);
          param_1[7] = (byte)(uVar3 >> (3 - (iVar2 + 7)) * 8);
          param_1 = param_1 + 8;
          iVar2 = iVar2 + 8;
          uVar5 = uVar5 - 1;
        } while (uVar5 != 0);
      }
      iVar1 = param_2 - iVar2;
      if (iVar2 < param_2) {
        do {
          *param_1 = (byte)(uVar3 >> (3 - iVar2) * 8);
          param_1 = param_1 + 1;
          iVar2 = iVar2 + 1;
          iVar1 = iVar1 + -1;
        } while (iVar1 != 0);
      }
    }
  }
  return 1;
}

