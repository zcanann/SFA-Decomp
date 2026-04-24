// Function: FUN_80255230
// Entry: 80255230
// Size: 512 bytes

undefined4 FUN_80255230(byte *param_1,uint param_2)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  byte *pbVar4;
  uint uVar5;
  uint local_20;
  byte local_1c [4];
  
  if (DAT_803ded20 == -0x5a00ffa6) {
    iVar3 = FUN_80254c34(DAT_803ded18,DAT_803ded1c,0);
    pbVar4 = param_1;
    if (iVar3 == 0) {
      uVar2 = 0;
    }
    else {
      for (; (uint)((int)pbVar4 - (int)param_1) < param_2; pbVar4 = pbVar4 + 1) {
        if (*pbVar4 == 10) {
          *pbVar4 = 0xd;
        }
      }
      local_1c[0] = 0xa0;
      local_1c[1] = 1;
      local_1c[2] = 0;
      local_1c[3] = 0;
      uVar2 = 0;
      while (param_2 != 0) {
        iVar3 = FUN_80254534(DAT_803ded18,DAT_803ded1c,3);
        if (iVar3 == 0) {
          uVar1 = 0xffffffff;
        }
        else {
          local_20 = 0x20010000;
          FUN_802539e0(DAT_803ded18,(byte *)&local_20,4,1,0);
          FUN_80253dc8(DAT_803ded18);
          FUN_802539e0(DAT_803ded18,(byte *)&local_20,1,0,0);
          FUN_80253dc8(DAT_803ded18);
          FUN_80254660(DAT_803ded18);
          uVar1 = 0x10 - (local_20 >> 0x18);
        }
        if ((int)uVar1 < 0) {
          uVar2 = 3;
          break;
        }
        if ((0xb < (int)uVar1) || (param_2 <= uVar1)) {
          iVar3 = FUN_80254534(DAT_803ded18,DAT_803ded1c,3);
          if (iVar3 == 0) {
            uVar2 = 3;
            break;
          }
          FUN_802539e0(DAT_803ded18,local_1c,4,1,0);
          FUN_80253dc8(DAT_803ded18);
          for (; ((uVar1 != 0 && (param_2 != 0)) && ((3 < (int)uVar1 || (param_2 <= uVar1))));
              param_2 = param_2 - uVar5) {
            uVar5 = param_2;
            if (3 < param_2) {
              uVar5 = 4;
            }
            FUN_802539e0(DAT_803ded18,param_1,uVar5,1,0);
            param_1 = param_1 + uVar5;
            uVar1 = uVar1 - uVar5;
            FUN_80253dc8(DAT_803ded18);
          }
          FUN_80254660(DAT_803ded18);
        }
      }
      FUN_80254d28(DAT_803ded18);
    }
  }
  else {
    uVar2 = 2;
  }
  return uVar2;
}

