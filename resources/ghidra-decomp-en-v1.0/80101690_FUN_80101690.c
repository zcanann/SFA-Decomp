// Function: FUN_80101690
// Entry: 80101690
// Size: 536 bytes

void FUN_80101690(uint param_1,undefined4 param_2)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  ushort **ppuVar5;
  undefined2 *puVar6;
  
  if (((DAT_803dd51c != (ushort *)0x0) && (DAT_803dd518 != (param_1 & 0xffff))) &&
     ((**(code **)(**(int **)((int)DAT_803dd51c + 4) + 0xc))(DAT_803dd524), iVar2 = DAT_803dd514,
     *(char *)((int)DAT_803dd51c + 8) == '\x01')) {
    FUN_80013e2c(*(undefined4 *)((&DAT_803a4228)[DAT_803dd514] + 4));
    FUN_80023800((&DAT_803a4228)[iVar2]);
    (&DAT_803a4228)[iVar2] = *(undefined4 *)(&DAT_803a4224 + (uint)DAT_803dd520 * 4);
    DAT_803dd520 = DAT_803dd520 - 1;
    DAT_803dd51c = (ushort *)0x0;
    DAT_803dd518 = 0xffffffff;
  }
  cVar1 = DAT_803dd500;
  DAT_803dd514 = 0;
  ppuVar5 = (ushort **)&DAT_803a4228;
  for (uVar3 = (uint)DAT_803dd520; uVar3 != 0; uVar3 = uVar3 - 1) {
    if ((param_1 & 0xffff) == (uint)**ppuVar5) goto LAB_801017a4;
    ppuVar5 = ppuVar5 + 1;
    DAT_803dd514 = DAT_803dd514 + 1;
  }
  DAT_803dd514 = -1;
LAB_801017a4:
  if (DAT_803dd514 == -1) {
    uVar4 = FUN_80023cc8(0xc,0xf,0);
    uVar3 = (uint)DAT_803dd520;
    (&DAT_803a4228)[uVar3] = uVar4;
    DAT_803dd520 = DAT_803dd520 + 1;
    puVar6 = (undefined2 *)(&DAT_803a4228)[uVar3];
    *puVar6 = (short)param_1;
    *(char *)(puVar6 + 4) = cVar1;
    uVar4 = FUN_80013ec8(param_1,4);
    *(undefined4 *)(puVar6 + 2) = uVar4;
    DAT_803dd514 = DAT_803dd520 - 1;
  }
  if (DAT_803dd514 == -1) {
    DAT_803dd51c = (ushort *)0x0;
    DAT_803dd518 = 0xffffffff;
  }
  else {
    DAT_803dd51c = (ushort *)(&DAT_803a4228)[DAT_803dd514];
    DAT_803dd518 = (uint)*DAT_803dd51c;
    (**(code **)(**(int **)(DAT_803dd51c + 2) + 4))(DAT_803dd524,(int)DAT_803dd501,param_2);
  }
  DAT_803dd508 = (int)DAT_803dd501;
  DAT_803dd50c = (int)DAT_803dd500;
  return;
}

