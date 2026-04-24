// Function: FUN_80124854
// Entry: 80124854
// Size: 324 bytes

undefined4 FUN_80124854(int param_1,undefined4 *param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  uint local_28 [2];
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  local_28[0] = DAT_803e1e10;
  iVar2 = FUN_80028424(*param_2,param_3);
  iVar2 = *(byte *)(iVar2 + 0x29) - 1;
  FUN_800528f0();
  if ((-1 < iVar2) && (iVar2 < 7)) {
    if ((&DAT_803a93c4)[iVar2] != 0) {
      if ((&DAT_803a93a8)[iVar2] == 0) {
        uStack28 = (uint)*(byte *)(param_1 + 0x37);
        local_20 = 0x43300000;
        uVar1 = (uint)(FLOAT_803e2010 *
                      (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1e88));
        local_18 = (longlong)(int)uVar1;
        local_28[0] = local_28[0] & 0xffffff00 | uVar1 & 0xff;
      }
      else {
        local_28[0] = local_28[0] & 0xffffff00 | (uint)*(byte *)(param_1 + 0x37);
      }
      FUN_80051fb8((&DAT_803a93c4)[iVar2],0,0,local_28,0,1);
      goto LAB_80124934;
    }
  }
  local_28[0] = local_28[0] & 0xffffff00;
  FUN_80052764(local_28);
LAB_80124934:
  FUN_800528bc();
  FUN_8025c584(1,4,5,5);
  FUN_80070310(0,7,0);
  FUN_800702b8(0);
  FUN_8025bff0(7,0,0,7,0);
  return 1;
}

