// Function: FUN_80260ecc
// Entry: 80260ecc
// Size: 156 bytes

undefined4 FUN_80260ecc(int param_1,ushort param_2,undefined4 param_3)

{
  uint uVar1;
  undefined4 uVar2;
  short *psVar3;
  
  if ((&DAT_803afe40)[param_1 * 0x44] == 0) {
    uVar2 = 0xfffffffd;
  }
  else {
    psVar3 = *(short **)(&DAT_803afec8 + param_1 * 0x110);
    while (param_2 != 0xffff) {
      uVar1 = (uint)param_2;
      if ((uVar1 < 5) || (*(ushort *)(&DAT_803afe50 + param_1 * 0x110) <= uVar1)) {
        return 0xfffffffa;
      }
      param_2 = psVar3[uVar1];
      psVar3[uVar1] = 0;
      psVar3[3] = psVar3[3] + 1;
    }
    uVar2 = FUN_80260f68(param_1,psVar3,param_3);
  }
  return uVar2;
}

