// Function: FUN_8028d960
// Entry: 8028d960
// Size: 380 bytes

void FUN_8028d960(int param_1,uint *param_2)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  uint uVar4;
  uint **ppuVar5;
  
  uVar4 = *param_2 & 0xfffffff8;
  *param_2 = *param_2 & 0xfffffffd;
  puVar3 = (uint *)((int)param_2 + uVar4);
  *puVar3 = *puVar3 & 0xfffffffb;
  puVar3[-1] = uVar4;
  ppuVar5 = (uint **)(param_1 + ((*(uint *)(param_1 + 0xc) & 0xfffffff8) - 4));
  if (*ppuVar5 == (uint *)0x0) {
    *ppuVar5 = param_2;
    param_2[2] = (uint)param_2;
    param_2[3] = (uint)param_2;
  }
  else {
    param_2[2] = (*ppuVar5)[2];
    *(uint **)(param_2[2] + 0xc) = param_2;
    param_2[3] = (uint)*ppuVar5;
    (*ppuVar5)[2] = (uint)param_2;
    *ppuVar5 = param_2;
    puVar3 = *ppuVar5;
    if (((*puVar3 & 4) == 0) && (uVar4 = puVar3[-1], (uVar4 & 2) == 0)) {
      puVar2 = (uint *)((int)puVar3 - uVar4);
      *puVar2 = *puVar2 & 7;
      *puVar2 = *puVar2 | uVar4 + (*puVar3 & 0xfffffff8) & 0xfffffff8;
      if ((*puVar2 & 2) == 0) {
        iVar1 = uVar4 + (*puVar3 & 0xfffffff8);
        *(int *)((int)puVar2 + iVar1 + -4) = iVar1;
      }
      if (*ppuVar5 == puVar3) {
        *ppuVar5 = (uint *)(*ppuVar5)[3];
      }
      *(uint *)(puVar3[3] + 8) = puVar3[2];
      *(uint *)(*(int *)(puVar3[3] + 8) + 0xc) = puVar3[3];
      puVar3 = puVar2;
    }
    *ppuVar5 = puVar3;
    FUN_8028d8a4(*ppuVar5,ppuVar5);
  }
  if (*(uint *)(param_1 + 8) < (**ppuVar5 & 0xfffffff8)) {
    *(uint *)(param_1 + 8) = **ppuVar5 & 0xfffffff8;
  }
  return;
}

