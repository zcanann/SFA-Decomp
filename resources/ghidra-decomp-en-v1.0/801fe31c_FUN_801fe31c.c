// Function: FUN_801fe31c
// Entry: 801fe31c
// Size: 580 bytes

void FUN_801fe31c(short *param_1,float *param_2)

{
  float fVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  undefined auStack40 [8];
  undefined4 local_20;
  uint uStack28;
  
  iVar4 = *(int *)(param_1 + 0x26);
  *(undefined *)((int)param_2 + 0x119) = 0;
  *param_1 = (ushort)*(byte *)(iVar4 + 0x1b) << 8;
  param_1[1] = 0;
  param_1[2] = 0;
  uStack28 = (uint)*(byte *)(iVar4 + 0x1a);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e61d8) * FLOAT_803e61d0;
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1c));
  if (iVar3 == 0) {
    uVar2 = 1;
  }
  else {
    uVar2 = 3;
  }
  *(undefined *)(param_2 + 0x46) = uVar2;
  if ((*(char *)(param_2 + 0x46) == '\x01') &&
     (iVar3 = FUN_801fe560((double)FLOAT_803e61c8,(double)FLOAT_803e61c8,param_1,auStack40,1),
     iVar3 == 0)) {
    *(undefined *)(param_2 + 0x46) = 2;
  }
  if (*(char *)(iVar4 + 0x26) != '\0') {
    *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 1;
    if (*(char *)(iVar4 + 0x26) == '\x02') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 2;
    }
    if (*(char *)(iVar4 + 0x26) == '\x03') {
      *(undefined *)(param_2 + 0x46) = 10;
    }
    if (*(char *)(iVar4 + 0x26) == '\x04') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 4;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) & 0xfe;
    }
    if (*(char *)(iVar4 + 0x26) == '\x05') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 8;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x10;
    }
    if (*(char *)(iVar4 + 0x26) == '\x06') {
      FUN_8002b884(param_1,1);
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 8;
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x10;
    }
    if (*(char *)(iVar4 + 0x26) == '\a') {
      *(byte *)((int)param_2 + 0x119) = *(byte *)((int)param_2 + 0x119) | 0x20;
    }
  }
  iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x24));
  if (iVar3 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 5;
  }
  *(undefined *)(param_2 + 0x46) = uVar2;
  if (*(char *)(param_2 + 0x46) == '\x05') {
    FUN_80037200(param_1,0x24);
  }
  fVar1 = FLOAT_803e61c8;
  *(float *)(param_1 + 0x12) = FLOAT_803e61c8;
  *(float *)(param_1 + 0x14) = fVar1;
  *(float *)(param_1 + 0x16) = fVar1;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  *param_2 = fVar1;
  return;
}

