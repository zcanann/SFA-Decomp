// Function: FUN_80253080
// Entry: 80253080
// Size: 228 bytes

void FUN_80253080(uint param_1)

{
  ushort uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined2 *puVar4;
  
  puVar4 = &DAT_8032e310;
  if (0xb < param_1) {
    param_1 = 0xb;
  }
  uVar2 = FUN_8024377c();
  DAT_803de090 = param_1;
  iVar3 = FUN_8024d900();
  if (iVar3 == 2) {
LAB_802530e8:
    puVar4 = &DAT_8032e310;
  }
  else {
    if (iVar3 < 2) {
      if (iVar3 == 0) goto LAB_802530e8;
      if (-1 < iVar3) {
        puVar4 = (undefined2 *)0x8032e340;
        goto LAB_8025310c;
      }
    }
    else if (iVar3 == 5) goto LAB_802530e8;
    FUN_8007d6dc(s_SISetSamplingRate__unknown_TV_fo_8032e370);
    param_1 = 0;
  }
LAB_8025310c:
  uVar1 = read_volatile_2(DAT_cc00206c);
  if ((uVar1 & 1) == 0) {
    iVar3 = 1;
  }
  else {
    iVar3 = 2;
  }
  FUN_802525e4(iVar3 * (uint)(ushort)puVar4[param_1 * 2],*(undefined *)(puVar4 + param_1 * 2 + 1));
  FUN_802437a4(uVar2);
  return;
}

