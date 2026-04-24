// Function: FUN_802462a8
// Entry: 802462a8
// Size: 288 bytes

undefined4
FUN_802462a8(int param_1,undefined4 param_2,undefined4 param_3,uint param_4,int param_5,int param_6,
            ushort param_7)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  if ((param_6 < 0) || (0x1f < param_6)) {
    uVar3 = 0;
  }
  else {
    *(undefined2 *)(param_1 + 0x2c8) = 1;
    uVar1 = param_4 & 0xfffffff8;
    *(ushort *)(param_1 + 0x2ca) = param_7 & 1;
    *(int *)(param_1 + 0x2d4) = param_6;
    *(int *)(param_1 + 0x2d0) = param_6;
    *(undefined4 *)(param_1 + 0x2cc) = 1;
    *(undefined4 *)(param_1 + 0x2d8) = 0xffffffff;
    *(undefined4 *)(param_1 + 0x2f0) = 0;
    *(undefined4 *)(param_1 + 0x2ec) = 0;
    *(undefined4 *)(param_1 + 0x2e8) = 0;
    *(undefined4 *)(param_1 + 0x2f8) = 0;
    *(undefined4 *)(param_1 + 0x2f4) = 0;
    *(undefined4 *)(uVar1 - 8) = 0;
    *(undefined4 *)(uVar1 - 4) = 0;
    FUN_80242498(param_1,param_2,uVar1 - 8);
    *(undefined **)(param_1 + 0x84) = &LAB_802463c8;
    *(undefined4 *)(param_1 + 0xc) = param_3;
    *(uint *)(param_1 + 0x304) = param_4;
    *(uint *)(param_1 + 0x308) = param_4 - param_5;
    **(undefined4 **)(param_1 + 0x308) = 0xdeadbabe;
    FUN_8024377c();
    iVar2 = param_1;
    if (DAT_800000e0 != 0) {
      *(int *)(DAT_800000e0 + 0x2fc) = param_1;
      iVar2 = DAT_800000dc;
    }
    DAT_800000dc = iVar2;
    *(int *)(param_1 + 0x300) = DAT_800000e0;
    *(undefined4 *)(param_1 + 0x2fc) = 0;
    DAT_800000e0 = param_1;
    FUN_802437a4();
    uVar3 = 1;
  }
  return uVar3;
}

