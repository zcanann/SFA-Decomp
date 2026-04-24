// Function: FUN_80274f20
// Entry: 80274f20
// Size: 296 bytes

undefined4 FUN_80274f20(undefined2 param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  
  iVar2 = 0;
  puVar1 = &DAT_803bfc78;
  DAT_803ca278 = param_1;
  while( true ) {
    if ((int)(uint)DAT_803de288 <= iVar2) {
      return 0xffffffff;
    }
    DAT_803de2a8 = FUN_80282ee8(&DAT_803ca278,*puVar1,*(undefined2 *)(puVar1 + 2),0x20,&LAB_80274f10
                               );
    if ((DAT_803de2a8 != 0) && (*(short *)(DAT_803de2a8 + 2) != -1)) break;
    puVar1 = puVar1 + 3;
    iVar2 = iVar2 + 1;
  }
  DAT_803de2ac = (undefined4 *)(DAT_803de2a8 + 0xc);
  *param_2 = *DAT_803de2ac;
  param_2[1] = *(undefined4 *)(DAT_803de2a8 + 8);
  param_2[3] = 0;
  param_2[5] = DAT_803de2ac[2];
  param_2[4] = DAT_803de2ac[1] & 0xffffff;
  param_2[6] = DAT_803de2ac[3];
  *(char *)(param_2 + 7) = (char)((uint)DAT_803de2ac[1] >> 0x18);
  if (*(int *)(DAT_803de2a8 + 0x1c) != 0) {
    param_2[2] = *(int *)(DAT_803de2a8 + 0x1c) + (&DAT_803bfc78)[iVar2 * 3];
  }
  return 0;
}

