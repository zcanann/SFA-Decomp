// Function: FUN_8010192c
// Entry: 8010192c
// Size: 536 bytes

void FUN_8010192c(uint param_1,undefined4 param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined2 *puVar6;
  
  if (((DAT_803de194 != (ushort *)0x0) && (DAT_803de190 != (param_1 & 0xffff))) &&
     ((**(code **)(**(int **)((int)DAT_803de194 + 4) + 0xc))(DAT_803de19c), iVar3 = DAT_803de18c,
     *(char *)((int)DAT_803de194 + 8) == '\x01')) {
    FUN_80013e4c(*(undefined **)((&DAT_803a4e88)[DAT_803de18c] + 4));
    FUN_800238c4((&DAT_803a4e88)[iVar3]);
    (&DAT_803a4e88)[iVar3] = *(undefined4 *)(&DAT_803a4e84 + (uint)DAT_803de198 * 4);
    DAT_803de198 = DAT_803de198 - 1;
    DAT_803de194 = (ushort *)0x0;
    DAT_803de190 = 0xffffffff;
  }
  cVar1 = DAT_803de178;
  DAT_803de18c = 0;
  puVar5 = &DAT_803a4e88;
  for (uVar2 = (uint)DAT_803de198; uVar2 != 0; uVar2 = uVar2 - 1) {
    if ((param_1 & 0xffff) == (uint)*(ushort *)*puVar5) goto LAB_80101a40;
    puVar5 = puVar5 + 1;
    DAT_803de18c = DAT_803de18c + 1;
  }
  DAT_803de18c = -1;
LAB_80101a40:
  if (DAT_803de18c == -1) {
    iVar3 = FUN_80023d8c(0xc,0xf);
    uVar2 = (uint)DAT_803de198;
    (&DAT_803a4e88)[uVar2] = iVar3;
    DAT_803de198 = DAT_803de198 + 1;
    puVar6 = (undefined2 *)(&DAT_803a4e88)[uVar2];
    *puVar6 = (short)param_1;
    *(char *)(puVar6 + 4) = cVar1;
    uVar4 = FUN_80013ee8(param_1);
    *(undefined4 *)(puVar6 + 2) = uVar4;
    DAT_803de18c = DAT_803de198 - 1;
  }
  if (DAT_803de18c == -1) {
    DAT_803de194 = (ushort *)0x0;
    DAT_803de190 = 0xffffffff;
  }
  else {
    DAT_803de194 = (ushort *)(&DAT_803a4e88)[DAT_803de18c];
    DAT_803de190 = (uint)*DAT_803de194;
    (**(code **)(**(int **)(DAT_803de194 + 2) + 4))(DAT_803de19c,(int)DAT_803de179,param_2);
  }
  DAT_803de184 = (int)DAT_803de178;
  DAT_803de180 = (int)DAT_803de179;
  return;
}

