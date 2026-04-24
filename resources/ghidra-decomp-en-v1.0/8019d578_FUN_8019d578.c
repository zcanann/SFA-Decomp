// Function: FUN_8019d578
// Entry: 8019d578
// Size: 444 bytes

undefined4 FUN_8019d578(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  short *psVar3;
  undefined4 local_28;
  int local_24;
  undefined4 local_20 [4];
  
  psVar3 = *(short **)(param_1 + 0xb8);
  local_28 = 0;
  while (iVar1 = FUN_800374ec(param_1,&local_24,local_20,&local_28), iVar1 != 0) {
    if (local_24 == 0x110001) {
      if ((*psVar3 == 0x54) && (0xaf < *(short *)(param_3 + 0x58))) {
        FUN_800378c4(local_20[0],0x110001,param_1,0);
      }
    }
    else if (local_24 < 0x110001) {
      if (local_24 == 0xa0005) {
        FUN_800200e8((int)*psVar3,1);
      }
    }
    else if (local_24 == 0x110003) {
      if ((*psVar3 == 0x56) && (0xaf < *(short *)(param_3 + 0x58))) {
        FUN_800378c4(local_20[0],0x110003,param_1,0);
      }
    }
    else if (((local_24 < 0x110003) && (*psVar3 == 0x55)) && (0xaf < *(short *)(param_3 + 0x58))) {
      FUN_800378c4(local_20[0],0x110002,param_1,0);
    }
  }
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if (((*(char *)(param_3 + iVar1 + 0x81) == '\x01') && (iVar2 = FUN_8001ffb4(0x54), iVar2 != 0))
       && ((iVar2 = FUN_8001ffb4(0x55), iVar2 != 0 && (iVar2 = FUN_8001ffb4(0x56), iVar2 != 0)))) {
      FUN_800200e8(0x4e0,1);
    }
  }
  return 0;
}

