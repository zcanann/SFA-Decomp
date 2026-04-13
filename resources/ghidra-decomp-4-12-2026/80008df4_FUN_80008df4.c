// Function: FUN_80008df4
// Entry: 80008df4
// Size: 232 bytes

void FUN_80008df4(undefined4 param_1,undefined4 param_2,uint *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_80286830();
  iVar1 = DAT_803dd438;
  uVar5 = (uint)uVar6;
  iVar4 = DAT_803dd438 + 1;
  iVar3 = DAT_803dd438 * 0x30;
  DAT_803dd438 = iVar4;
  if (0xf < iVar4) {
    DAT_803dd438 = 0;
  }
  if ((uVar6 & 0x1f) != 0) {
    uVar5 = (uVar5 | 0x1f) + 1;
  }
  uVar2 = FUN_80023d8c(uVar5,0);
  *param_3 = uVar2;
  (&DAT_803365c0)[iVar1 * 0xc] = param_4;
  (&DAT_803365c4)[iVar1 * 0xc] = param_5;
  (&DAT_803365c8)[iVar1 * 0xc] = param_6;
  (&DAT_803365cc)[iVar1 * 0xc] = param_7;
  FUN_802420e0(uVar2,uVar5);
  DAT_803dd43c = 0;
  FUN_802514c8((undefined4 *)(&DAT_803365a0 + iVar3),100,1,1,(int)(uVar6 >> 0x20),uVar2,uVar5,
               -0x7fff7124);
  FUN_8028687c();
  return;
}

