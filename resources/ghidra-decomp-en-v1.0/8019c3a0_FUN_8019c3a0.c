// Function: FUN_8019c3a0
// Entry: 8019c3a0
// Size: 252 bytes

undefined4 FUN_8019c3a0(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_28 = DAT_802c22d8;
  local_24 = DAT_802c22dc;
  local_20 = DAT_802c22e0;
  local_1c = DAT_802c22e4;
  if (*(short *)(param_1 + 0xb4) < 0) {
    FUN_800e8370();
    uVar1 = 0;
  }
  else {
    if (*(char *)(iVar3 + 0xa80) == '\x06') {
      puVar4 = &local_20;
    }
    else {
      puVar4 = &local_28;
    }
    iVar2 = FUN_80080340(param_3);
    if ((iVar2 == 0x283) ||
       (iVar3 = FUN_80114bb0(param_1,param_3,iVar3,(int)(short)*puVar4,(int)(short)puVar4[1]),
       iVar3 == 0)) {
      if (*(char *)(param_3 + 0x80) == '\x02') {
        uVar1 = FUN_8002b9ec();
        FUN_80296a24(uVar1,10);
      }
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}

