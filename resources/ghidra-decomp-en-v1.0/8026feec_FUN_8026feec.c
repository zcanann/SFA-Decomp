// Function: FUN_8026feec
// Entry: 8026feec
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x8026ff44) */

int FUN_8026feec(uint param_1,char param_2,undefined4 param_3,uint param_4,undefined4 param_5,
                undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined param_9,
                undefined2 param_10,undefined2 param_11,undefined param_12,char param_13,
                undefined param_14,undefined4 param_15)

{
  uint uVar1;
  ushort uVar3;
  int iVar2;
  int iVar4;
  undefined4 local_3c;
  
  param_2 = param_2 + param_13;
  uVar1 = param_1 & 0xc000;
  if (uVar1 == 0x4000) {
    iVar2 = FUN_8026fc8c(param_1,param_2,param_3,param_1,param_4,param_5,param_6,param_7,param_8,
                         param_9,param_10,param_11,1,param_12,param_14,param_15);
    if (iVar2 != -1) {
      uVar1 = FUN_8027949c(iVar2);
      while (uVar1 != 0xffffffff) {
        iVar4 = (uVar1 & 0xff) * 0x404;
        *(undefined *)(DAT_803de268 + iVar4 + 0x11c) = 0;
        uVar1 = *(uint *)(DAT_803de268 + iVar4 + 0xec);
      }
    }
  }
  else {
    if (uVar1 < 0x4000) {
      if (uVar1 == 0) {
        uVar3 = FUN_80281b24(0x41,param_7,param_8);
        if (uVar3 < 0x1f81) {
          iVar2 = -1;
          uVar1 = 1;
        }
        else {
          iVar2 = FUN_8026f630(param_4 & 0x7f,param_7,param_8,1,&local_3c);
          uVar1 = countLeadingZeros(local_3c);
          uVar1 = uVar1 >> 5;
        }
        if (uVar1 == 0) {
          return -1;
        }
        if (iVar2 != -1) {
          return iVar2;
        }
        iVar2 = FUN_80278b94(param_1,param_2,param_3,param_1,param_4,param_5,param_6,param_7,param_8
                             ,param_9,param_10,param_11,1,param_12,param_14,param_15);
        return iVar2;
      }
    }
    else if (uVar1 == 0x8000) {
      iVar2 = FUN_8026f8b8(param_1,param_2,param_3,param_1,param_4,param_5,param_6,param_7,param_8,
                           param_9,param_10,param_11,1,param_12,param_14,param_15);
      if (iVar2 == -1) {
        return -1;
      }
      uVar1 = FUN_8027949c(iVar2);
      while (uVar1 != 0xffffffff) {
        iVar4 = (uVar1 & 0xff) * 0x404;
        *(undefined *)(DAT_803de268 + iVar4 + 0x11c) = 0;
        uVar1 = *(uint *)(DAT_803de268 + iVar4 + 0xec);
      }
      return iVar2;
    }
    iVar2 = -1;
  }
  return iVar2;
}

