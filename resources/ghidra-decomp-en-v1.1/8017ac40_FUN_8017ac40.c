// Function: FUN_8017ac40
// Entry: 8017ac40
// Size: 488 bytes

void FUN_8017ac40(short *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  char *pcVar4;
  undefined *puVar5;
  
  pcVar4 = *(char **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  if (*(byte *)(param_2 + 0x1d) == 0) {
    *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
  }
  else {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - DOUBLE_803e43b8) *
         *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e43c0;
  }
  FUN_80035a6c((int)param_1,
               (short)((int)((uint)*(byte *)(param_2 + 0x1d) *
                            (uint)*(byte *)(*(int *)(param_1 + 0x28) + 0x62)) >> 6));
  *(char *)((int)param_1 + 0xad) = (char)((int)(uint)*(byte *)(param_2 + 0x1e) >> 2);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  if (*(int *)(param_1 + 0x18) == 0) {
    *(undefined2 *)(pcVar4 + 2) = *(undefined2 *)(param_2 + 0x18);
  }
  else {
    iVar3 = *(int *)(*(int *)(param_1 + 0x18) + 0x4c);
    if (iVar3 == 0) {
      pcVar4[2] = -1;
      pcVar4[3] = -1;
    }
    else {
      iVar3 = FUN_80080284((int *)&DAT_80321c58,2,*(int *)(iVar3 + 0x14));
      *(short *)(pcVar4 + 2) = (short)iVar3;
    }
  }
  uVar1 = FUN_80020078((int)*(short *)(pcVar4 + 2));
  *pcVar4 = (char)uVar1;
  if (*pcVar4 == '\0') {
    puVar5 = *(undefined **)(param_1 + 0x5c);
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0;
    }
    *puVar5 = 0;
  }
  else {
    puVar5 = *(undefined **)(param_1 + 0x5c);
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
    *puVar5 = 1;
  }
  if ((*(byte *)(param_2 + 0x23) & 1) == 0) {
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  return;
}

