// Function: FUN_80025894
// Entry: 80025894
// Size: 176 bytes

uint FUN_80025894(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  
  if (param_10 == 0) {
    for (uVar2 = param_11 << 2; (uVar2 & 7) != 0; uVar2 = uVar2 + 1) {
    }
    FUN_800490c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x31,DAT_803dd7e0,
                 (param_9 & 0xfffffffc) << 2,0x20,param_13,param_14,param_15,param_16);
    iVar1 = (param_9 & 3) * 4;
    uVar2 = uVar2 + (*(int *)(DAT_803dd7e0 + iVar1 + 4) - *(int *)(DAT_803dd7e0 + iVar1));
  }
  else {
    for (uVar2 = param_11 * 2 + 8; (uVar2 & 7) != 0; uVar2 = uVar2 + 1) {
    }
  }
  return uVar2;
}

