// Function: FUN_80275684
// Entry: 80275684
// Size: 296 bytes

undefined4 FUN_80275684(undefined2 param_1,undefined4 *param_2)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  piVar1 = &DAT_803c08d8;
  DAT_803caed8 = param_1;
  while( true ) {
    if ((int)(uint)DAT_803def08 <= iVar2) {
      return 0xffffffff;
    }
    DAT_803def28 = FUN_8028364c(&DAT_803caed8,*piVar1,(uint)*(ushort *)(piVar1 + 2),0x20,
                                &LAB_80275674);
    if ((DAT_803def28 != 0) && (*(short *)(DAT_803def28 + 2) != -1)) break;
    piVar1 = piVar1 + 3;
    iVar2 = iVar2 + 1;
  }
  DAT_803def2c = (undefined4 *)(DAT_803def28 + 0xc);
  *param_2 = *DAT_803def2c;
  param_2[1] = *(undefined4 *)(DAT_803def28 + 8);
  param_2[3] = 0;
  param_2[5] = DAT_803def2c[2];
  param_2[4] = DAT_803def2c[1] & 0xffffff;
  param_2[6] = DAT_803def2c[3];
  *(char *)(param_2 + 7) = (char)((uint)DAT_803def2c[1] >> 0x18);
  if (*(int *)(DAT_803def28 + 0x1c) != 0) {
    param_2[2] = *(int *)(DAT_803def28 + 0x1c) + (&DAT_803c08d8)[iVar2 * 3];
  }
  return 0;
}

