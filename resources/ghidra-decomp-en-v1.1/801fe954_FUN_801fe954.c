// Function: FUN_801fe954
// Entry: 801fe954
// Size: 580 bytes

void FUN_801fe954(short *param_1,undefined4 *param_2)

{
  float fVar1;
  undefined uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  float afStack_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar5 = *(int *)(param_1 + 0x26);
  *(undefined *)((int)param_2 + 0x119) = 0;
  *param_1 = (ushort)*(byte *)(iVar5 + 0x1b) << 8;
  param_1[1] = 0;
  param_1[2] = 0;
  uStack_1c = (uint)*(byte *)(iVar5 + 0x1a);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6e70) * FLOAT_803e6e68;
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x1c));
  if (uVar3 == 0) {
    uVar2 = 1;
  }
  else {
    uVar2 = 3;
  }
  *(undefined *)(param_2 + 0x46) = uVar2;
  if ((*(char *)(param_2 + 0x46) == '\x01') &&
     (iVar4 = FUN_801feb98((double)FLOAT_803e6e60,(double)FLOAT_803e6e60,(int)param_1,afStack_28,1),
     iVar4 == 0)) {
    *(undefined *)(param_2 + 0x46) = 2;
  }
  if (*(char *)(iVar5 + 0x26) != '\0') {
    *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 1;
    if (*(char *)(iVar5 + 0x26) == '\x02') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 2;
    }
    if (*(char *)(iVar5 + 0x26) == '\x03') {
      *(undefined *)(param_2 + 0x46) = 10;
    }
    if (*(char *)(iVar5 + 0x26) == '\x04') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 4;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) & 0xfe;
    }
    if (*(char *)(iVar5 + 0x26) == '\x05') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 8;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x10;
    }
    if (*(char *)(iVar5 + 0x26) == '\x06') {
      FUN_8002b95c((int)param_1,1);
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 8;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x10;
    }
    if (*(char *)(iVar5 + 0x26) == '\a') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x20;
    }
  }
  uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x24));
  if (uVar3 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 5;
  }
  *(undefined *)(param_2 + 0x46) = uVar2;
  if (*(char *)(param_2 + 0x46) == '\x05') {
    FUN_800372f8((int)param_1,0x24);
  }
  fVar1 = FLOAT_803e6e60;
  *(float *)(param_1 + 0x12) = FLOAT_803e6e60;
  *(float *)(param_1 + 0x14) = fVar1;
  *(float *)(param_1 + 0x16) = fVar1;
  param_1[0x7c] = 0;
  param_1[0x7d] = 0;
  *param_2 = fVar1;
  return;
}

