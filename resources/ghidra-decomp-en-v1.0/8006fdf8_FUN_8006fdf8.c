// Function: FUN_8006fdf8
// Entry: 8006fdf8
// Size: 220 bytes

undefined4 FUN_8006fdf8(int param_1,int param_2,int param_3)

{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  
  bVar1 = false;
  if ((((-1 < param_1) && (param_1 < 0x280)) && (-1 < param_2)) && (param_2 < 0x1e0)) {
    bVar1 = true;
  }
  if (!bVar1) {
    return 0;
  }
  if (param_1 < 0x10) {
    param_1 = 0x10;
  }
  if (param_2 < 6) {
    param_2 = 6;
  }
  uVar4 = (uint)DAT_803dd000;
  if (uVar4 < 0x14) {
    (&DAT_803966d0)[uVar4 * 6] = (short)param_1;
    (&DAT_803966d2)[uVar4 * 6] = (short)param_2;
    (&DAT_803966d8)[uVar4 * 3] = param_3;
    DAT_803dd000 = DAT_803dd000 + 1;
  }
  iVar3 = 0;
  puVar2 = &DAT_803965e0;
  uVar4 = (uint)DAT_803dd002;
  while( true ) {
    if (uVar4 == 0) {
      return 0;
    }
    if (param_3 == *(int *)(puVar2 + 4)) break;
    puVar2 = puVar2 + 6;
    iVar3 = iVar3 + 1;
    uVar4 = uVar4 - 1;
  }
  return (&DAT_803965e4)[iVar3 * 3];
}

