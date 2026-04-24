// Function: FUN_80023f98
// Entry: 80023f98
// Size: 200 bytes

int FUN_80023f98(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint *puVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  int *piVar6;
  
  uVar4 = (uint)DAT_803dd7c2;
  DAT_803dd7c2 = DAT_803dd7c2 + 1;
  (&DAT_80341300)[uVar4 * 5] = param_3;
  piVar6 = &DAT_80341304 + uVar4 * 5;
  *piVar6 = 0;
  piVar5 = &DAT_80341308 + uVar4 * 5;
  *piVar5 = param_1;
  (&DAT_8034130c)[uVar4 * 5] = param_2;
  *(undefined4 *)(&DAT_80341310 + uVar4 * 0x14) = 0;
  iVar3 = *piVar5;
  for (iVar1 = 0; iVar1 < (int)(&DAT_80341300)[uVar4 * 5]; iVar1 = iVar1 + 1) {
    *(short *)(iVar3 + 0xe) = (short)iVar1;
    iVar3 = iVar3 + 0x1c;
  }
  puVar2 = (uint *)*piVar5;
  uVar4 = param_1 + param_3 * 0x1c;
  if ((uVar4 & 0x1f) == 0) {
    *puVar2 = uVar4;
  }
  else {
    *puVar2 = (uVar4 & 0xffffffe0) + 0x20;
  }
  puVar2[1] = param_2 + param_3 * -0x1c;
  *(undefined2 *)(puVar2 + 2) = 0;
  *(undefined2 *)((int)puVar2 + 10) = 0xffff;
  *(undefined2 *)(puVar2 + 3) = 0xffff;
  *piVar6 = *piVar6 + 1;
  return *piVar5;
}

