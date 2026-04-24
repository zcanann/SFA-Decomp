// Function: FUN_80172f14
// Entry: 80172f14
// Size: 776 bytes

void FUN_80172f14(short *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined local_28 [4];
  undefined4 local_24;
  undefined4 local_20;
  uint uStack28;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  local_24 = DAT_803e3440;
  local_28[0] = DAT_803e3444;
  FUN_80037200(param_1,4);
  FUN_80037964(param_1,2);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1b) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x22) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x23) << 8;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
  *(code **)(param_1 + 0x5e) = FUN_80172680;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x26);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined *)(iVar4 + 0xc) = *(undefined *)(param_2 + 0x19);
  *(undefined *)(iVar4 + 0xd) = *(undefined *)(param_2 + 0x1a);
  *(undefined *)(iVar4 + 0xf) = 0;
  *(undefined4 *)(iVar4 + 0x18) = 0xfffffffe;
  *(undefined *)(iVar4 + 0x1d) = 0;
  *(undefined2 *)(iVar4 + 0x14) = *(undefined2 *)(param_2 + 0x24);
  *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(iVar4 + 0x24) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(iVar4 + 0x28) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(iVar4 + 0x2c) = *(undefined4 *)(param_1 + 10);
  *(undefined *)(iVar4 + 0x36) = *(undefined *)(param_2 + 0x27);
  *(undefined *)(iVar4 + 0x3e) = 0;
  if (*(short *)(iVar4 + 0x14) != -1) {
    uVar3 = FUN_8001ffb4();
    uVar2 = countLeadingZeros(uVar3);
    *(char *)(iVar4 + 0x1e) = (char)(uVar2 >> 5);
  }
  *(undefined2 *)(iVar4 + 0x10) = *(undefined2 *)(param_2 + 0x1c);
  if (*(short *)(iVar4 + 0x10) == -1) {
    *(undefined4 *)(param_1 + 0x7a) = 0;
  }
  else {
    uVar3 = FUN_8001ffb4();
    *(undefined4 *)(param_1 + 0x7a) = uVar3;
  }
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (*(int *)(*(int *)(param_1 + 0x28) + 0x18) == 0) {
      *(float *)(iVar4 + 4) = FLOAT_803e3494;
    }
    else {
      uStack28 = (int)*(char *)(*(int *)(*(int *)(param_1 + 0x28) + 0x18) + 8) ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar4 + 4) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3448);
    }
    if (*(int *)(*(int *)(param_1 + 0x28) + 0x40) != 0) {
      uStack28 = (uint)*(byte *)(*(int *)(*(int *)(param_1 + 0x28) + 0x40) + 0xc) << 2 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar4 + 4) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3448);
    }
    if (((*(uint *)(*(int *)(param_1 + 0x28) + 0x44) & 0x10000) != 0) &&
       (*(char *)(iVar4 + 0x36) != '\0')) {
      *(undefined *)(iVar4 + 0x38) = *(undefined *)(param_2 + 0x28);
      *(undefined *)(iVar4 + 0x39) = *(undefined *)(param_2 + 0x29);
      *(undefined *)(iVar4 + 0x3a) = *(undefined *)(param_2 + 0x2a);
    }
    sVar1 = param_1[0x23];
    if (sVar1 == 0x3cd) {
      *(float *)(iVar4 + 0x40) = FLOAT_803e349c;
      *(float *)(iVar4 + 0x44) = FLOAT_803e3498;
    }
    else if ((sVar1 < 0x3cd) && (sVar1 == 0xb)) {
      *(float *)(iVar4 + 0x40) = FLOAT_803e345c;
      *(float *)(iVar4 + 0x44) = FLOAT_803e3498;
    }
    else {
      *(float *)(iVar4 + 0x40) = FLOAT_803e34a0;
    }
    (**(code **)(*DAT_803dcaa8 + 4))(iVar4 + 0x50,0,0x40006,1);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar4 + 0x50,1,&DAT_80320c58,&local_24,local_28);
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar4 + 0x50);
  }
  return;
}

