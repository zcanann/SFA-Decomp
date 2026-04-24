// Function: FUN_8028d8a4
// Entry: 8028d8a4
// Size: 188 bytes

void FUN_8028d8a4(uint *param_1,uint **param_2)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = *param_1 & 0xfffffff8;
  puVar1 = (uint *)((int)param_1 + uVar3);
  uVar2 = *puVar1;
  if ((uVar2 & 2) != 0) {
    return;
  }
  *param_1 = *param_1 & 7;
  uVar3 = uVar3 + (uVar2 & 0xfffffff8);
  *param_1 = *param_1 | uVar3;
  if ((*param_1 & 2) == 0) {
    *(uint *)((int)param_1 + (uVar3 - 4)) = uVar3;
  }
  if ((*param_1 & 2) == 0) {
    *(uint *)((int)param_1 + uVar3) = *(uint *)((int)param_1 + uVar3) & 0xfffffffb;
  }
  else {
    *(uint *)((int)param_1 + uVar3) = *(uint *)((int)param_1 + uVar3) | 4;
  }
  if (*param_2 == puVar1) {
    *param_2 = (uint *)(*param_2)[3];
  }
  if (*param_2 == puVar1) {
    *param_2 = (uint *)0x0;
  }
  *(uint *)(puVar1[3] + 8) = puVar1[2];
  *(uint *)(puVar1[2] + 0xc) = puVar1[3];
  return;
}

