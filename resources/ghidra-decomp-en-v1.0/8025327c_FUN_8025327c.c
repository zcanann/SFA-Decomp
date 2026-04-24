// Function: FUN_8025327c
// Entry: 8025327c
// Size: 604 bytes

undefined4 FUN_8025327c(int param_1,byte *param_2,int param_3,int param_4,undefined4 param_5)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  
  iVar1 = param_1 * 0x40;
  uVar3 = FUN_8024377c();
  if (((*(uint *)(&DAT_803ae40c + iVar1) & 3) == 0) && ((*(uint *)(&DAT_803ae40c + iVar1) & 4) != 0)
     ) {
    *(undefined4 *)(&DAT_803ae404 + iVar1) = param_5;
    if (*(int *)(&DAT_803ae404 + iVar1) != 0) {
      FUN_8025389c(param_1,0,1,0);
      FUN_80243bcc(0x200000 >> param_1 * 3);
    }
    *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) | 2;
    if (param_4 != 0) {
      iVar5 = 0;
      uVar6 = 0;
      if (0 < param_3) {
        if ((8 < param_3) && (uVar7 = param_3 - 1U >> 3, pbVar4 = param_2, 0 < param_3 + -8)) {
          do {
            uVar6 = uVar6 | (uint)*pbVar4 << (3 - iVar5) * 8 |
                    (uint)pbVar4[1] << (3 - (iVar5 + 1)) * 8 |
                    (uint)pbVar4[2] << (3 - (iVar5 + 2)) * 8 | (uint)pbVar4[3] << iVar5 * -8 |
                    (uint)pbVar4[4] << (3 - (iVar5 + 4)) * 8 |
                    (uint)pbVar4[5] << (3 - (iVar5 + 5)) * 8 |
                    (uint)pbVar4[6] << (3 - (iVar5 + 6)) * 8 |
                    (uint)pbVar4[7] << (3 - (iVar5 + 7)) * 8;
            pbVar4 = pbVar4 + 8;
            iVar5 = iVar5 + 8;
            uVar7 = uVar7 - 1;
          } while (uVar7 != 0);
        }
        pbVar4 = param_2 + iVar5;
        iVar2 = param_3 - iVar5;
        if (iVar5 < param_3) {
          do {
            uVar6 = uVar6 | (uint)*pbVar4 << (3 - iVar5) * 8;
            pbVar4 = pbVar4 + 1;
            iVar5 = iVar5 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
      *(uint *)(&DAT_cc006810 + param_1 * 0x14) = uVar6;
    }
    *(byte **)(&DAT_803ae414 + iVar1) = param_2;
    iVar5 = param_3;
    if (param_4 == 1) {
      iVar5 = 0;
    }
    *(int *)(&DAT_803ae410 + iVar1) = iVar5;
    *(uint *)(&DAT_cc00680c + param_1 * 0x14) = param_4 << 2 | 1U | (param_3 + -1) * 0x10;
    FUN_802437a4(uVar3);
    uVar3 = 1;
  }
  else {
    FUN_802437a4(uVar3);
    uVar3 = 0;
  }
  return uVar3;
}

