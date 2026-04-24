// Function: FUN_8019daf4
// Entry: 8019daf4
// Size: 444 bytes

undefined4
FUN_8019daf4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,int param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  short *psVar3;
  uint local_28;
  uint local_24;
  uint local_20 [4];
  
  psVar3 = *(short **)(param_9 + 0xb8);
  local_28 = 0;
  while (iVar1 = FUN_800375e4(param_9,&local_24,local_20,&local_28), iVar1 != 0) {
    if (local_24 == 0x110001) {
      if ((*psVar3 == 0x54) && (0xaf < *(short *)(param_11 + 0x58))) {
        FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                     0x110001,param_9,0,param_13,param_14,param_15,param_16);
      }
    }
    else if ((int)local_24 < 0x110001) {
      if (local_24 == 0xa0005) {
        param_1 = FUN_800201ac((int)*psVar3,1);
      }
    }
    else if (local_24 == 0x110003) {
      if ((*psVar3 == 0x56) && (0xaf < *(short *)(param_11 + 0x58))) {
        FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                     0x110003,param_9,0,param_13,param_14,param_15,param_16);
      }
    }
    else if ((((int)local_24 < 0x110003) && (*psVar3 == 0x55)) &&
            (0xaf < *(short *)(param_11 + 0x58))) {
      FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                   0x110002,param_9,0,param_13,param_14,param_15,param_16);
    }
  }
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    if (((*(char *)(param_11 + iVar1 + 0x81) == '\x01') && (uVar2 = FUN_80020078(0x54), uVar2 != 0))
       && ((uVar2 = FUN_80020078(0x55), uVar2 != 0 && (uVar2 = FUN_80020078(0x56), uVar2 != 0)))) {
      FUN_800201ac(0x4e0,1);
    }
  }
  return 0;
}

