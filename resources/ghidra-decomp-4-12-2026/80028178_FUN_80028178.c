// Function: FUN_80028178
// Entry: 80028178
// Size: 336 bytes

void FUN_80028178(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  uint uStack_28;
  uint local_24;
  uint local_20 [8];
  
  uVar6 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar4 = (int)uVar6;
  local_24 = 0;
  uVar6 = FUN_800490c4(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x52,
                       &local_24,iVar4 << 2,4,param_13,param_14,param_15,param_16);
  if ((local_24 & 0x10000000) == 0) {
    local_24 = *(uint *)(DAT_803dd7cc + iVar4 * 4);
    uVar6 = FUN_80046644(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,0,
                         local_24,0,local_20,iVar4,1,param_16);
    puVar3 = &uStack_28;
    uVar5 = 0;
    uVar6 = FUN_80046644(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,
                         param_12 + 0x80,local_24,local_20[0],puVar3,iVar4,0,param_16);
    uVar2 = (*(byte *)(iVar1 + 0xf3) - 1 & 0xfffffff8) + 8;
    FUN_800490c4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,param_12,
                 *(int *)(iVar1 + 0x80) + param_11 * uVar2,uVar2,puVar3,iVar4,uVar5,param_16);
  }
  else {
    uVar6 = FUN_80046644(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x51,0,
                         local_24,0,local_20,iVar4,1,param_16);
    puVar3 = &uStack_28;
    uVar5 = 0;
    uVar6 = FUN_80046644(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x51,
                         param_12 + 0x80,local_24,local_20[0],puVar3,iVar4,0,param_16);
    uVar2 = (*(byte *)(iVar1 + 0xf3) - 1 & 0xfffffff8) + 8;
    FUN_800490c4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,param_12,
                 *(int *)(iVar1 + 0x80) + param_11 * uVar2,uVar2,puVar3,iVar4,uVar5,param_16);
  }
  FUN_8028688c();
  return;
}

