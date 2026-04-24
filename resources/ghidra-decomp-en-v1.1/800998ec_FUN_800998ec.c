// Function: FUN_800998ec
// Entry: 800998ec
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x80099c20) */
/* WARNING: Removing unreachable block (ram,0x800998fc) */

void FUN_800998ec(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  double dVar2;
  float local_38;
  undefined auStack_34 [6];
  undefined2 local_2e;
  float local_2c;
  
  switch(param_2) {
  case 0:
    iVar1 = 10;
    dVar2 = (double)FLOAT_803dffd8;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar2;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a0,auStack_34,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803e0010;
    break;
  case 1:
    iVar1 = 10;
    dVar2 = (double)FLOAT_803dffd4;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar2;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a0,auStack_34,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    iVar1 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a0,0,1,0xffffffff,0);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803dffd4;
    break;
  case 2:
    iVar1 = 10;
    dVar2 = (double)FLOAT_803dffd4;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar2;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a1,auStack_34,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    iVar1 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a1,0,1,0xffffffff,0);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803dffd4;
    break;
  case 3:
    iVar1 = 10;
    dVar2 = (double)FLOAT_803dffd8;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar2;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a6,auStack_34,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803e0010;
    break;
  case 4:
    iVar1 = 10;
    dVar2 = (double)FLOAT_803dffd4;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar2;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a6,auStack_34,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    iVar1 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a6,0,1,0xffffffff,0);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803dffd4;
    break;
  case 5:
    return;
  case 6:
    iVar1 = 10;
    dVar2 = (double)FLOAT_803dffd8;
    do {
      local_2e = (undefined2)iVar1;
      local_2c = (float)dVar2;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a1,auStack_34,1,0xffffffff,0);
      iVar1 = iVar1 + 2;
    } while (iVar1 < 0x14);
    local_38 = FLOAT_803e0010;
    break;
  default:
    goto switchD_80099928_caseD_7;
  }
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x79f,0,1,0xffffffff,&local_38);
switchD_80099928_caseD_7:
  return;
}

