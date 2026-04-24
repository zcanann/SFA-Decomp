// Function: FUN_80124794
// Entry: 80124794
// Size: 192 bytes

undefined4 FUN_80124794(int param_1,undefined4 *param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  uint local_18 [4];
  
  local_18[0] = DAT_803e1e14;
  iVar1 = FUN_80028424(*param_2,param_3);
  FUN_800528f0();
  local_18[0] = local_18[0] & 0xffffff00 | (uint)*(byte *)(param_1 + 0x37);
  uVar2 = FUN_800536c0(*(undefined4 *)(iVar1 + 0x24));
  FUN_80051fb8(uVar2,0,0,local_18,0,1);
  FUN_800528bc();
  FUN_8025c584(1,4,5,5);
  FUN_80070310(0,7,0);
  FUN_800702b8(0);
  FUN_8025bff0(7,0,0,7,0);
  return 1;
}

