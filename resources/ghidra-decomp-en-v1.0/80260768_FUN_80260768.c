// Function: FUN_80260768
// Entry: 80260768
// Size: 156 bytes

undefined4 FUN_80260768(int param_1,ushort param_2)

{
  uint uVar1;
  undefined4 uVar2;
  ushort *puVar3;
  int iVar4;
  
  if ((&DAT_803af1e0)[param_1 * 0x44] == 0) {
    uVar2 = 0xfffffffd;
  }
  else {
    iVar4 = *(int *)(&DAT_803af268 + param_1 * 0x110);
    while (param_2 != 0xffff) {
      uVar1 = (uint)param_2;
      if ((uVar1 < 5) || (*(ushort *)(&DAT_803af1f0 + param_1 * 0x110) <= uVar1)) {
        return 0xfffffffa;
      }
      puVar3 = (ushort *)(iVar4 + uVar1 * 2);
      param_2 = *puVar3;
      *puVar3 = 0;
      *(short *)(iVar4 + 6) = *(short *)(iVar4 + 6) + 1;
    }
    uVar2 = FUN_80260804(param_1,iVar4);
  }
  return uVar2;
}

