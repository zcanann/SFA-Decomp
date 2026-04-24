// Function: FUN_801aab60
// Entry: 801aab60
// Size: 232 bytes

void FUN_801aab60(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0x1c2);
  if ((uVar1 == 0) && (uVar1 = FUN_80020078(0xa3), uVar1 != 0)) {
    iVar2 = FUN_8002bac4();
    dVar4 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    if (dVar4 < (double)FLOAT_803e52fc) {
      FUN_800201ac(0x1c2,1);
    }
  }
  uVar1 = FUN_80020078(0x1c3);
  if (uVar1 == 0) {
    FUN_8002fb40((double)FLOAT_803e5300,(double)FLOAT_803dc074);
    FUN_80115330();
    FUN_8003b408(param_1,iVar3 + 0x624);
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    FUN_80035ff8(param_1);
  }
  return;
}

