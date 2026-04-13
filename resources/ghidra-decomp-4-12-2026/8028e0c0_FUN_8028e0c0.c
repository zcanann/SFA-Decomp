// Function: FUN_8028e0c0
// Entry: 8028e0c0
// Size: 380 bytes

void FUN_8028e0c0(int param_1,uint *param_2)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar4 = *param_2 & 0xfffffff8;
  *param_2 = *param_2 & 0xfffffffd;
  puVar3 = (uint *)((int)param_2 + uVar4);
  *puVar3 = *puVar3 & 0xfffffffb;
  puVar3[-1] = uVar4;
  puVar3 = (uint *)(param_1 + ((*(uint *)(param_1 + 0xc) & 0xfffffff8) - 4));
  if (*puVar3 == 0) {
    *puVar3 = (uint)param_2;
    param_2[2] = (uint)param_2;
    param_2[3] = (uint)param_2;
  }
  else {
    param_2[2] = *(uint *)(*puVar3 + 8);
    *(uint **)(param_2[2] + 0xc) = param_2;
    param_2[3] = *puVar3;
    *(uint **)(*puVar3 + 8) = param_2;
    *puVar3 = (uint)param_2;
    puVar5 = (uint *)*puVar3;
    if (((*puVar5 & 4) == 0) && (uVar4 = puVar5[-1], (uVar4 & 2) == 0)) {
      puVar2 = (uint *)((int)puVar5 - uVar4);
      *puVar2 = *puVar2 & 7;
      *puVar2 = *puVar2 | uVar4 + (*puVar5 & 0xfffffff8) & 0xfffffff8;
      if ((*puVar2 & 2) == 0) {
        iVar1 = uVar4 + (*puVar5 & 0xfffffff8);
        *(int *)((int)puVar2 + iVar1 + -4) = iVar1;
      }
      if ((uint *)*puVar3 == puVar5) {
        *puVar3 = ((uint *)*puVar3)[3];
      }
      *(uint *)(puVar5[3] + 8) = puVar5[2];
      *(uint *)(*(int *)(puVar5[3] + 8) + 0xc) = puVar5[3];
      puVar5 = puVar2;
    }
    *puVar3 = (uint)puVar5;
    FUN_8028e004((uint *)*puVar3,puVar3);
  }
  if (*(uint *)(param_1 + 8) < (*(uint *)*puVar3 & 0xfffffff8)) {
    *(uint *)(param_1 + 8) = *(uint *)*puVar3 & 0xfffffff8;
  }
  return;
}

