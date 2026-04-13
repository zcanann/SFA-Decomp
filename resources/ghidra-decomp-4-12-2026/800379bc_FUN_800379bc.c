// Function: FUN_800379bc
// Entry: 800379bc
// Size: 160 bytes

uint FUN_800379bc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,uint param_11,uint param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  uint *puVar2;
  
  if ((param_9 != 0) && (puVar2 = *(uint **)(param_9 + 0xdc), puVar2 != (uint *)0x0)) {
    uVar1 = *puVar2;
    if (uVar1 < puVar2[1]) {
      puVar2[uVar1 * 3 + 2] = param_10;
      puVar2[uVar1 * 3 + 3] = param_11;
      puVar2[uVar1 * 3 + 4] = param_12;
      *puVar2 = *puVar2 + 1;
      return *puVar2;
    }
    FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_objmsg___x___overflow_in_object___802cba20,param_10,
                 (int)*(short *)(param_9 + 0x44),(int)*(short *)(param_9 + 0x46),
                 (int)*(short *)(param_11 + 0x46),param_9,param_15,param_16);
  }
  return 0;
}

