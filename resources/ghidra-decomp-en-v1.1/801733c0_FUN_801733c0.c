// Function: FUN_801733c0
// Entry: 801733c0
// Size: 776 bytes

void FUN_801733c0(short *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  undefined local_28 [4];
  undefined4 local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  local_24 = DAT_803e40d8;
  local_28[0] = DAT_803e40dc;
  FUN_800372f8((int)param_1,4);
  FUN_80037a5c((int)param_1,2);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1b) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x22) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x23) << 8;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
  *(code **)(param_1 + 0x5e) = FUN_80172b2c;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x26);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined *)(iVar3 + 0xc) = *(undefined *)(param_2 + 0x19);
  *(undefined *)(iVar3 + 0xd) = *(undefined *)(param_2 + 0x1a);
  *(undefined *)(iVar3 + 0xf) = 0;
  *(undefined4 *)(iVar3 + 0x18) = 0xfffffffe;
  *(undefined *)(iVar3 + 0x1d) = 0;
  *(undefined2 *)(iVar3 + 0x14) = *(undefined2 *)(param_2 + 0x24);
  *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(iVar3 + 0x24) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(iVar3 + 0x28) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(param_1 + 10);
  *(undefined *)(iVar3 + 0x36) = *(undefined *)(param_2 + 0x27);
  *(undefined *)(iVar3 + 0x3e) = 0;
  if ((int)*(short *)(iVar3 + 0x14) != 0xffffffff) {
    uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x14));
    uVar2 = countLeadingZeros(uVar2);
    *(char *)(iVar3 + 0x1e) = (char)(uVar2 >> 5);
  }
  *(undefined2 *)(iVar3 + 0x10) = *(undefined2 *)(param_2 + 0x1c);
  if ((int)*(short *)(iVar3 + 0x10) == 0xffffffff) {
    param_1[0x7a] = 0;
    param_1[0x7b] = 0;
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x10));
    *(uint *)(param_1 + 0x7a) = uVar2;
  }
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (*(int *)(*(int *)(param_1 + 0x28) + 0x18) == 0) {
      *(float *)(iVar3 + 4) = FLOAT_803e412c;
    }
    else {
      uStack_1c = (int)*(char *)(*(int *)(*(int *)(param_1 + 0x28) + 0x18) + 8) ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar3 + 4) = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e40e0);
    }
    if (*(int *)(*(int *)(param_1 + 0x28) + 0x40) != 0) {
      uStack_1c = (uint)*(byte *)(*(int *)(*(int *)(param_1 + 0x28) + 0x40) + 0xc) << 2 ^ 0x80000000
      ;
      local_20 = 0x43300000;
      *(float *)(iVar3 + 4) = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e40e0);
    }
    if (((*(uint *)(*(int *)(param_1 + 0x28) + 0x44) & 0x10000) != 0) &&
       (*(char *)(iVar3 + 0x36) != '\0')) {
      *(undefined *)(iVar3 + 0x38) = *(undefined *)(param_2 + 0x28);
      *(undefined *)(iVar3 + 0x39) = *(undefined *)(param_2 + 0x29);
      *(undefined *)(iVar3 + 0x3a) = *(undefined *)(param_2 + 0x2a);
    }
    sVar1 = param_1[0x23];
    if (sVar1 == 0x3cd) {
      *(float *)(iVar3 + 0x40) = FLOAT_803e4134;
      *(float *)(iVar3 + 0x44) = FLOAT_803e4130;
    }
    else if ((sVar1 < 0x3cd) && (sVar1 == 0xb)) {
      *(float *)(iVar3 + 0x40) = FLOAT_803e40f4;
      *(float *)(iVar3 + 0x44) = FLOAT_803e4130;
    }
    else {
      *(float *)(iVar3 + 0x40) = FLOAT_803e4138;
    }
    (**(code **)(*DAT_803dd728 + 4))(iVar3 + 0x50,0,0x40006,1);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar3 + 0x50,1,&DAT_803218a8,&local_24,local_28);
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3 + 0x50);
  }
  return;
}

