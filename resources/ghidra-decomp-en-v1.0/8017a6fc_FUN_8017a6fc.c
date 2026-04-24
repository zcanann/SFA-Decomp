// Function: FUN_8017a6fc
// Entry: 8017a6fc
// Size: 488 bytes

void FUN_8017a6fc(short *param_1,int param_2)

{
  undefined2 uVar2;
  char cVar3;
  undefined4 *puVar1;
  int iVar4;
  char *pcVar5;
  undefined *puVar6;
  
  pcVar5 = *(char **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  if (*(byte *)(param_2 + 0x1d) == 0) {
    *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
  }
  else {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - DOUBLE_803e3720) *
         *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e3728;
  }
  FUN_80035974(param_1,(short)((int)((uint)*(byte *)(param_2 + 0x1d) *
                                    (uint)*(byte *)(*(int *)(param_1 + 0x28) + 0x62)) >> 6));
  *(char *)((int)param_1 + 0xad) = (char)((int)(uint)*(byte *)(param_2 + 0x1e) >> 2);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  if (*(int *)(param_1 + 0x18) == 0) {
    *(undefined2 *)(pcVar5 + 2) = *(undefined2 *)(param_2 + 0x18);
  }
  else {
    iVar4 = *(int *)(*(int *)(param_1 + 0x18) + 0x4c);
    if (iVar4 == 0) {
      *(undefined2 *)(pcVar5 + 2) = 0xffff;
    }
    else {
      uVar2 = FUN_8007fff8(&DAT_80321008,2,*(undefined4 *)(iVar4 + 0x14));
      *(undefined2 *)(pcVar5 + 2) = uVar2;
    }
  }
  cVar3 = FUN_8001ffb4((int)*(short *)(pcVar5 + 2));
  *pcVar5 = cVar3;
  if (*pcVar5 == '\0') {
    puVar6 = *(undefined **)(param_1 + 0x5c);
    puVar1 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = 0;
    }
    *puVar6 = 0;
  }
  else {
    puVar6 = *(undefined **)(param_1 + 0x5c);
    puVar1 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = 0x100;
    }
    *puVar6 = 1;
  }
  if ((*(byte *)(param_2 + 0x23) & 1) == 0) {
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  return;
}

