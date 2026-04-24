// Function: FUN_80008df4
// Entry: 80008df4
// Size: 232 bytes

void FUN_80008df4(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_802860cc();
  iVar1 = DAT_803dc7b8;
  uVar5 = (uint)uVar6;
  iVar4 = DAT_803dc7b8 + 1;
  iVar3 = DAT_803dc7b8 * 0x30;
  DAT_803dc7b8 = iVar4;
  if (0xf < iVar4) {
    DAT_803dc7b8 = 0;
  }
  if ((uVar6 & 0x1f) != 0) {
    uVar5 = (uVar5 | 0x1f) + 1;
  }
  uVar2 = FUN_80023cc8(uVar5,0,0);
  *param_3 = uVar2;
  (&DAT_80335960)[iVar1 * 0xc] = param_4;
  (&DAT_80335964)[iVar1 * 0xc] = param_5;
  (&DAT_80335968)[iVar1 * 0xc] = param_6;
  (&DAT_8033596c)[iVar1 * 0xc] = param_7;
  FUN_802419e8(uVar2,uVar5);
  DAT_803dc7bc = 0;
  FUN_80250d64(&DAT_80335940 + iVar3,100,1,1,(int)(uVar6 >> 0x20),uVar2,uVar5,FUN_80008edc);
  FUN_80286118();
  return;
}

