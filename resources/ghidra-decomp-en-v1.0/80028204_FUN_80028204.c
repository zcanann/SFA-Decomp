// Function: FUN_80028204
// Entry: 80028204
// Size: 336 bytes

char * FUN_80028204(int param_1,undefined4 param_2,short param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  char *local_28;
  undefined4 local_24;
  undefined auStack32 [16];
  
  uVar1 = FUN_800430ac(0);
  if ((((uVar1 & 0x100000) == 0) || (*(short *)(param_1 + 4) == 1)) ||
     (*(short *)(param_1 + 4) == 3)) {
    if (param_4 == 0) {
      iVar3 = (int)(short)param_2;
      iVar2 = FUN_80013c10(DAT_803dcb50,iVar3,&local_28);
      if (iVar2 == 0) {
        uVar4 = *(undefined4 *)(DAT_803dcb4c + iVar3 * 4);
        FUN_800464c8(0x30,0,uVar4,0,&local_24,iVar3,1);
        local_28 = (char *)FUN_80023cc8(local_24,10,0);
        FUN_800464c8(0x30,local_28,uVar4,local_24,auStack32,iVar3,0);
        *local_28 = '\x01';
        FUN_80013ce8(DAT_803dcb50,param_2,&local_28);
      }
      else {
        *local_28 = *local_28 + '\x01';
      }
    }
    else {
      local_28 = (char *)FUN_800280b4(param_1,(int)(short)param_2,(int)param_3,param_4);
    }
  }
  else {
    local_28 = (char *)0x0;
  }
  return local_28;
}

