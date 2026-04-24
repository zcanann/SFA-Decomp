// Function: FUN_800282c8
// Entry: 800282c8
// Size: 336 bytes

char * FUN_800282c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                   int param_9,short param_10,short param_11,int param_12,undefined4 param_13,
                   undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  char *local_28;
  uint local_24;
  uint auStack_20 [4];
  
  uVar1 = FUN_800431a4();
  if ((((uVar1 & 0x100000) == 0) || (*(short *)(param_9 + 4) == 1)) ||
     (*(short *)(param_9 + 4) == 3)) {
    if (param_12 == 0) {
      iVar3 = (int)param_10;
      iVar2 = FUN_80013c30(DAT_803dd7d0,iVar3,(uint)&local_28);
      if (iVar2 == 0) {
        uVar1 = *(uint *)(DAT_803dd7cc + iVar3 * 4);
        uVar4 = FUN_80046644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,0,
                             uVar1,0,&local_24,iVar3,1,param_16);
        local_28 = (char *)FUN_80023d8c(local_24,10);
        FUN_80046644(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,local_28,
                     uVar1,local_24,auStack_20,iVar3,0,param_16);
        *local_28 = '\x01';
        FUN_80013d08(DAT_803dd7d0,param_10,(uint)&local_28);
      }
      else {
        *local_28 = *local_28 + '\x01';
      }
    }
    else {
      local_28 = (char *)FUN_80028178(param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                                      param_8,param_9,(int)param_10,(int)param_11,param_12,param_13,
                                      param_14,param_15,param_16);
    }
  }
  else {
    local_28 = (char *)0x0;
  }
  return local_28;
}

