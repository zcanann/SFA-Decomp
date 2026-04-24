// Function: FUN_80024764
// Entry: 80024764
// Size: 536 bytes

void FUN_80024764(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,uint param_5,
                 uint param_6,uint param_7,uint param_8,short param_9)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  double extraout_f1;
  undefined8 uVar6;
  int local_88;
  undefined auStack_84 [4];
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
  
  uVar6 = FUN_80286840();
  piVar4 = (int *)uVar6;
  iVar5 = *piVar4;
  local_88 = piVar4[(*(ushort *)(piVar4 + 6) & 1) + 3];
  if ((param_8 & 0x10) != 0) {
    *(float *)(param_3 + 4) = (float)(extraout_f1 * (double)*(float *)(param_3 + 0x14));
  }
  uVar2 = param_5 & 0xff;
  local_24 = *(undefined *)(param_3 + uVar2 + 0x60);
  iVar3 = param_3 + uVar2 * 4;
  local_70 = *(undefined4 *)(iVar3 + 0x14);
  local_80 = *(undefined4 *)(iVar3 + 4);
  local_50 = *(undefined4 *)(iVar3 + 0x34);
  local_23 = *(undefined *)(param_3 + (param_6 & 0xff) + 0x60);
  iVar3 = param_3 + (param_6 & 0xff) * 4;
  local_6c = *(undefined4 *)(iVar3 + 0x14);
  local_7c = *(undefined4 *)(iVar3 + 4);
  uVar1 = param_7 & 0xff;
  local_4c = *(undefined4 *)(param_3 + uVar1 * 4 + 0x34);
  if ((*(ushort *)(iVar5 + 2) & 0x40) == 0) {
    local_40 = *(undefined2 *)(param_3 + uVar2 * 2 + 0x44);
    local_3e = *(undefined2 *)(param_3 + uVar1 * 2 + 0x44);
  }
  else {
    local_40 = 0;
    local_3e = 1;
    local_68 = *(undefined4 *)(param_3 + (uint)*(ushort *)(param_3 + uVar2 * 2 + 0x44) * 4 + 0x1c);
    if (uVar1 < 2) {
      local_64 = *(undefined4 *)(param_3 + (uint)*(ushort *)(param_3 + uVar1 * 2 + 0x44) * 4 + 0x1c)
      ;
    }
    else {
      local_64 = *(undefined4 *)(param_3 + (uint)*(ushort *)(param_3 + uVar1 * 2 + 0x44) * 4 + 0x24)
      ;
    }
  }
  if (param_9 == 0) {
    param_9 = 1;
  }
  local_2c = param_9;
  FUN_800245e8(iVar5,(int)auStack_84,2);
  uVar2 = param_8 & 0xf;
  if ((param_8 & 0xc) == 0) {
    if ((*(byte *)(param_3 + 99) & 1) != 0) {
      uVar2 = uVar2 | 0x10;
    }
    if ((*(byte *)(param_3 + 99) & 4) != 0) {
      uVar2 = uVar2 | 0x20;
    }
  }
  FUN_80006c6c(&local_88,(float *)((ulonglong)uVar6 >> 0x20),(int)auStack_84,
               *(undefined4 *)(iVar5 + 0x3c),(uint)*(byte *)(iVar5 + 0xf3),-0x7fcbec60,param_4,uVar2
              );
  FUN_8028688c();
  return;
}

