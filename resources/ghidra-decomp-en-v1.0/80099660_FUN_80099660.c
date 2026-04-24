// Function: FUN_80099660
// Entry: 80099660
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x80099994) */

void FUN_80099660(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  double dVar3;
  float local_38;
  undefined auStack52 [6];
  undefined2 local_2e;
  float local_2c;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  switch(param_2) {
  case 0:
    iVar1 = 10;
    dVar3 = (double)FLOAT_803df358;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar3;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a0,auStack52,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803df390;
    break;
  case 1:
    iVar1 = 10;
    dVar3 = (double)FLOAT_803df354;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar3;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a0,auStack52,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    iVar1 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a0,0,1,0xffffffff,0);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803df354;
    break;
  case 2:
    iVar1 = 10;
    dVar3 = (double)FLOAT_803df354;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar3;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a1,auStack52,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    iVar1 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a1,0,1,0xffffffff,0);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803df354;
    break;
  case 3:
    iVar1 = 10;
    dVar3 = (double)FLOAT_803df358;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar3;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a6,auStack52,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803df390;
    break;
  case 4:
    iVar1 = 10;
    dVar3 = (double)FLOAT_803df354;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar3;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a6,auStack52,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    iVar1 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a6,0,1,0xffffffff,0);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803df354;
    break;
  case 5:
    goto switchD_8009969c_caseD_7;
  case 6:
    iVar1 = 10;
    dVar3 = (double)FLOAT_803df358;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar3;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7a1,auStack52,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803df390;
    break;
  default:
    goto switchD_8009969c_caseD_7;
  }
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x79f,0,1,0xffffffff,&local_38);
switchD_8009969c_caseD_7:
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

