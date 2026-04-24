// Function: FUN_80171a24
// Entry: 80171a24
// Size: 384 bytes

void FUN_80171a24(undefined2 *param_1,int param_2)

{
  float fVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  undefined2 local_78;
  undefined2 local_76;
  undefined2 local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined auStack96 [64];
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  uStack28 = *(byte *)(param_2 + 0x2a) ^ 0x80000000;
  local_20 = 0x43300000;
  local_18 = 0x43300000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3438);
  if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3438) < FLOAT_803e3424) {
    fVar1 = FLOAT_803e3424;
  }
  *(float *)(param_1 + 4) = fVar1 * FLOAT_803e3428;
  *param_1 = (short)((int)(short)(ushort)*(byte *)(param_2 + 0x29) << 8);
  local_78 = *param_1;
  local_76 = param_1[1];
  local_74 = param_1[2];
  local_70 = FLOAT_803e3420;
  local_6c = FLOAT_803e342c;
  local_68 = FLOAT_803e342c;
  local_64 = FLOAT_803e342c;
  uStack20 = uStack28;
  FUN_80021ee8(auStack96,&local_78);
  FUN_800226cc((double)FLOAT_803e342c,(double)FLOAT_803e342c,(double)FLOAT_803e3420,auStack96,
               iVar4 + 0x10,iVar4 + 0x14,iVar4 + 0x18);
  *(float *)(iVar4 + 0x1c) =
       -(*(float *)(param_1 + 10) * *(float *)(iVar4 + 0x18) +
        *(float *)(param_1 + 6) * *(float *)(iVar4 + 0x10) +
        *(float *)(param_1 + 8) * *(float *)(iVar4 + 0x14));
  *(float *)(iVar4 + 0x20) = FLOAT_803e3430 * *(float *)(param_1 + 4);
  iVar3 = 0;
  do {
    uVar2 = FUN_800221a0(0,0xf0);
    *(undefined2 *)(iVar4 + 0x34) = uVar2;
    iVar4 = iVar4 + 2;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  *(int *)(param_1 + 0x7a) = (int)*(char *)(param_2 + 0x28);
  param_1[0x58] = param_1[0x58] | 0xa000;
  return;
}

