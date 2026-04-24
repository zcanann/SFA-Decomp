// Function: FUN_801f817c
// Entry: 801f817c
// Size: 296 bytes

void FUN_801f817c(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  float local_18 [4];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e5fb8;
  iVar1 = FUN_8003687c(param_1,0,0,0);
  if (iVar1 == 0) {
    if (*(char *)(iVar3 + 0x299) < '\0') {
      if ((*(ushort *)(iVar3 + 0x294) & 0x10) == 0) {
        uVar2 = FUN_8002b9ec();
      }
      else {
        uVar2 = FUN_80036e58(10,param_1,local_18);
      }
      FUN_80036450(uVar2,param_1,0xb,1,0);
      *(undefined *)(iVar3 + 0x296) = 6;
      *(byte *)(iVar3 + 0x299) = *(byte *)(iVar3 + 0x299) & 0x7f;
    }
  }
  else if ((*(ushort *)(iVar3 + 0x294) & 0x100) == 0) {
    if (*(int *)(*(int *)(param_1 + 0x4c) + 0x14) == 0) {
      FUN_80035f00(param_1);
      FUN_8002cbc4(param_1);
    }
    else {
      FUN_8002ce88(param_1);
      FUN_80035f00(param_1);
      FUN_80036fa4(param_1,3);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    }
  }
  else {
    *(undefined *)(iVar3 + 0x296) = 6;
  }
  return;
}

