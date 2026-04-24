// Function: FUN_800246a0
// Entry: 800246a0
// Size: 536 bytes

void FUN_800246a0(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,uint param_5,
                 uint param_6,uint param_7,uint param_8,short param_9)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  double extraout_f1;
  undefined8 uVar5;
  int local_88;
  undefined auStack132 [4];
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 local_40;
  undefined2 local_3e;
  short local_2c;
  undefined local_24;
  undefined local_23;
  
  uVar5 = FUN_802860dc();
  piVar3 = (int *)uVar5;
  iVar4 = *piVar3;
  local_88 = piVar3[(*(ushort *)(piVar3 + 6) & 1) + 3];
  if ((param_8 & 0x10) != 0) {
    *(float *)(param_3 + 4) = (float)(extraout_f1 * (double)*(float *)(param_3 + 0x14));
  }
  param_5 = param_5 & 0xff;
  local_24 = *(undefined *)(param_3 + param_5 + 0x60);
  iVar2 = param_3 + param_5 * 4;
  local_70 = *(undefined4 *)(iVar2 + 0x14);
  local_80 = *(undefined4 *)(iVar2 + 4);
  local_50 = *(undefined4 *)(iVar2 + 0x34);
  local_23 = *(undefined *)(param_3 + (param_6 & 0xff) + 0x60);
  iVar2 = param_3 + (param_6 & 0xff) * 4;
  local_6c = *(undefined4 *)(iVar2 + 0x14);
  local_7c = *(undefined4 *)(iVar2 + 4);
  param_7 = param_7 & 0xff;
  local_4c = *(undefined4 *)(param_3 + param_7 * 4 + 0x34);
  if ((*(ushort *)(iVar4 + 2) & 0x40) == 0) {
    local_40 = *(undefined2 *)(param_3 + param_5 * 2 + 0x44);
    local_3e = *(undefined2 *)(param_3 + param_7 * 2 + 0x44);
  }
  else {
    local_40 = 0;
    local_3e = 1;
    local_68 = *(undefined4 *)(param_3 + (uint)*(ushort *)(param_3 + param_5 * 2 + 0x44) * 4 + 0x1c)
    ;
    if (param_7 < 2) {
      local_64 = *(undefined4 *)
                  (param_3 + (uint)*(ushort *)(param_3 + param_7 * 2 + 0x44) * 4 + 0x1c);
    }
    else {
      local_64 = *(undefined4 *)
                  (param_3 + (uint)*(ushort *)(param_3 + param_7 * 2 + 0x44) * 4 + 0x24);
    }
  }
  if (param_9 == 0) {
    param_9 = 1;
  }
  local_2c = param_9;
  FUN_80024524(iVar4,auStack132,2);
  uVar1 = param_8 & 0xf;
  if ((param_8 & 0xc) == 0) {
    if ((*(byte *)(param_3 + 99) & 1) != 0) {
      uVar1 = uVar1 | 0x10;
    }
    if ((*(byte *)(param_3 + 99) & 4) != 0) {
      uVar1 = uVar1 | 0x20;
    }
  }
  FUN_80006c6c(&local_88,(int)((ulonglong)uVar5 >> 0x20),auStack132,*(undefined4 *)(iVar4 + 0x3c),
               *(undefined *)(iVar4 + 0xf3),&DAT_80340740,param_4,uVar1);
  FUN_80286128();
  return;
}

