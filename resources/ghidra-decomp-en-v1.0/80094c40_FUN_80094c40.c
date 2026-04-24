// Function: FUN_80094c40
// Entry: 80094c40
// Size: 796 bytes

void FUN_80094c40(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,uint param_5)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar2 = FUN_800e84f8();
  if (((param_3 != 0) && ((*(byte *)(param_3 + 0x58) & 2) != 0)) &&
     (*(short *)(iVar2 + 10) = *(short *)(param_3 + 0x24) + -1, (*(byte *)(param_3 + 0x59) & 1) != 0
     )) {
    DAT_803db618 = uRam803db61c;
    uRam803db61c = param_5 & 0xffff;
    DAT_8039ab40 = (undefined)(int)(*(float *)(param_3 + 8) / FLOAT_803df2dc);
    DAT_8039ab41 = 0;
    DAT_8039ab42 = (*(byte *)(param_3 + 0x59) & 4) == 0;
    uVar1 = (uint)*(byte *)(param_3 + 0x5d);
    if (uVar1 == 0) {
      if (DAT_8039ab28 != 0) {
        FUN_8002cbc4();
        DAT_8039ab28 = 0;
      }
      DAT_8039ab34 = 0;
    }
    else if ((uVar1 < 5) && (DAT_8039ab34 != *(int *)(&DAT_8030f7b0 + uVar1 * 4))) {
      if (DAT_8039ab28 != 0) {
        FUN_8002cbc4();
      }
      uVar3 = FUN_8002bdf4(0x20,*(undefined4 *)(&DAT_8030f7b0 + (uint)*(byte *)(param_3 + 0x5d) * 4)
                          );
      DAT_8039ab28 = FUN_8002df90(uVar3,4,0xffffffff,0xffffffff,0);
      DAT_8039ab34 = *(int *)(&DAT_8030f7b0 + (uint)*(byte *)(param_3 + 0x5d) * 4);
    }
    uVar1 = (uint)*(byte *)(param_3 + 0x5b);
    if (uVar1 == 0) {
      if (DAT_8039ab2c != 0) {
        FUN_8002cbc4();
        DAT_8039ab2c = 0;
      }
      DAT_8039ab38 = 0;
    }
    else if ((uVar1 < 4) && (DAT_8039ab38 != *(int *)(&DAT_8030f7c4 + uVar1 * 4))) {
      if (DAT_8039ab2c != 0) {
        FUN_8002cbc4();
      }
      uVar3 = FUN_8002bdf4(0x20,*(undefined4 *)(&DAT_8030f7c4 + (uint)*(byte *)(param_3 + 0x5b) * 4)
                          );
      DAT_8039ab2c = FUN_8002df90(uVar3,4,0xffffffff,0xffffffff,0);
      DAT_8039ab38 = *(int *)(&DAT_8030f7c4 + (uint)*(byte *)(param_3 + 0x5b) * 4);
    }
    uVar1 = (uint)*(byte *)(param_3 + 0x5a);
    if (uVar1 == 0) {
      if (DAT_8039ab30 != 0) {
        FUN_8002cbc4();
        DAT_8039ab30 = 0;
      }
      DAT_8039ab3c = 0;
    }
    else if ((uVar1 < 5) && (DAT_8039ab3c != *(int *)(&DAT_8030f7d4 + uVar1 * 4))) {
      if (DAT_8039ab30 != 0) {
        FUN_8002cbc4();
      }
      uVar3 = FUN_8002bdf4(0x20,*(undefined4 *)(&DAT_8030f7d4 + (uint)*(byte *)(param_3 + 0x5a) * 4)
                          );
      DAT_8039ab30 = FUN_8002df90(uVar3,4,0xffffffff,0xffffffff,0);
      DAT_8039ab3c = *(int *)(&DAT_8030f7d4 + (uint)*(byte *)(param_3 + 0x5a) * 4);
    }
  }
  return;
}

