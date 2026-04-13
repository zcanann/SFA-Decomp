// Function: FUN_801f87b4
// Entry: 801f87b4
// Size: 296 bytes

void FUN_801f87b4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  float local_18 [4];
  
  iVar2 = *(int *)(param_9 + 0xb8);
  local_18[0] = FLOAT_803e6c50;
  iVar1 = FUN_80036974(param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 == 0) {
    if (*(char *)(iVar2 + 0x299) < '\0') {
      if ((*(ushort *)(iVar2 + 0x294) & 0x10) == 0) {
        iVar1 = FUN_8002bac4();
      }
      else {
        iVar1 = FUN_80036f50(10,param_9,local_18);
      }
      FUN_80036548(iVar1,param_9,'\v',1,0);
      *(undefined *)(iVar2 + 0x296) = 6;
      *(byte *)(iVar2 + 0x299) = *(byte *)(iVar2 + 0x299) & 0x7f;
    }
  }
  else if ((*(ushort *)(iVar2 + 0x294) & 0x100) == 0) {
    if (*(int *)(*(int *)(param_9 + 0x4c) + 0x14) == 0) {
      uVar3 = FUN_80035ff8(param_9);
      FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    else {
      FUN_8002cf80(param_9);
      FUN_80035ff8(param_9);
      FUN_8003709c(param_9,3);
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
    }
  }
  else {
    *(undefined *)(iVar2 + 0x296) = 6;
  }
  return;
}

