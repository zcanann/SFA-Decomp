// Function: FUN_801e912c
// Entry: 801e912c
// Size: 500 bytes

void FUN_801e912c(short *param_1,int param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  double dVar5;
  undefined2 local_38;
  undefined local_36;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  local_38 = DAT_803e5a70;
  local_36 = DAT_803e5a72;
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uStack44 = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e5a8c *
                                        (float)((double)CONCAT44(0x43300000,uStack44) -
                                               DOUBLE_803e5a98)) / FLOAT_803e5a90));
  *(float *)(param_1 + 0x12) = (float)-dVar5;
  uStack36 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar5 = (double)FUN_80294204((double)((FLOAT_803e5a8c *
                                        (float)((double)CONCAT44(0x43300000,uStack36) -
                                               DOUBLE_803e5a98)) / FLOAT_803e5a90));
  *(float *)(param_1 + 0x16) = (float)-dVar5;
  *(char *)((int)param_1 + 0xad) = '\x01' - *(char *)(param_2 + 0x19);
  uStack28 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
  local_20 = 0x43300000;
  *pfVar4 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5a98);
  uStack20 = FUN_800221a0(0,100);
  uStack20 = uStack20 ^ 0x80000000;
  local_18 = 0x43300000;
  pfVar4[1] = FLOAT_803e5a94 +
              (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e5a98) / FLOAT_803e5a80;
  pfVar4[2] = *(float *)(param_2 + 0x14);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  FUN_8000dcbc(param_1,0x406);
  iVar2 = FUN_8002b588(param_1);
  cVar1 = *(char *)(param_2 + 0x19);
  if (cVar1 == '\x01') {
    *(undefined2 *)(pfVar4 + 3) = 0x42;
    *(undefined2 *)((int)pfVar4 + 0xe) = 1;
    *(undefined2 *)(pfVar4 + 4) = 0;
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    iVar3 = FUN_800221a0(0,2);
    *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = *(undefined *)((int)&local_38 + iVar3);
    *(undefined2 *)(pfVar4 + 3) = 0x41;
    *(undefined2 *)((int)pfVar4 + 0xe) = 4;
    *(undefined2 *)(pfVar4 + 4) = 2;
  }
  return;
}

