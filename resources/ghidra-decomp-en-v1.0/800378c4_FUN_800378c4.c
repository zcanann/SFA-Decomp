// Function: FUN_800378c4
// Entry: 800378c4
// Size: 160 bytes

uint FUN_800378c4(int param_1,uint param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint *puVar2;
  
  if ((param_1 != 0) && (puVar2 = *(uint **)(param_1 + 0xdc), puVar2 != (uint *)0x0)) {
    uVar1 = *puVar2;
    if (uVar1 < puVar2[1]) {
      puVar2[uVar1 * 3 + 2] = param_2;
      puVar2[uVar1 * 3 + 3] = param_3;
      puVar2[uVar1 * 3 + 4] = param_4;
      *puVar2 = *puVar2 + 1;
      return *puVar2;
    }
    FUN_801378a8(s_objmsg___x___overflow_in_object___802cae48,param_2,
                 (int)*(short *)(param_1 + 0x44),(int)*(short *)(param_1 + 0x46),
                 (int)*(short *)(param_3 + 0x46));
  }
  return 0;
}

