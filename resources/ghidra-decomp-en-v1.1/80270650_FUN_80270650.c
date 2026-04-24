// Function: FUN_80270650
// Entry: 80270650
// Size: 664 bytes

void FUN_80270650(uint param_1,int param_2,undefined4 param_3,uint param_4,byte param_5,uint param_6
                 ,uint param_7,uint param_8,undefined param_9,ushort param_10,undefined2 param_11,
                 undefined param_12,short param_13,undefined param_14,int param_15)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  short sVar5;
  byte bVar6;
  undefined4 local_3c;
  
  uVar1 = param_2 + param_13 & 0xff;
  if (0xff < uVar1) {
    uVar1 = 0xff;
  }
  uVar2 = param_1 & 0xc000;
  sVar5 = (short)param_1;
  bVar6 = (byte)param_8;
  if (uVar2 == 0x4000) {
    uVar1 = FUN_802703f0(sVar5,(short)uVar1,param_3,param_1,param_4,param_5,param_6,param_7,bVar6,
                         param_9,param_10,param_11,1,param_12,param_14,param_15);
    if (uVar1 != 0xffffffff) {
      uVar1 = FUN_80279c00(uVar1);
      while (uVar1 != 0xffffffff) {
        iVar4 = (uVar1 & 0xff) * 0x404;
        *(undefined *)(DAT_803deee8 + iVar4 + 0x11c) = 0;
        uVar1 = *(uint *)(DAT_803deee8 + iVar4 + 0xec);
      }
    }
  }
  else if (uVar2 < 0x4000) {
    if (uVar2 == 0) {
      uVar2 = FUN_80282288(0x41,param_7,param_8);
      if ((uVar2 & 0xffff) < 0x1f81) {
        uVar3 = 0xffffffff;
        uVar2 = 1;
      }
      else {
        uVar3 = param_4 & 0x7f;
        uVar2 = FUN_8026fd94((byte)uVar3,(char)param_7,bVar6,1,&local_3c);
        param_10 = (ushort)uVar2;
        uVar2 = countLeadingZeros(local_3c);
        uVar2 = uVar2 >> 5;
      }
      if ((uVar2 != 0) && (uVar3 == 0xffffffff)) {
        FUN_802792f8(param_1,(byte)uVar1,(byte)param_3,sVar5,(byte)param_4,param_5,(char)param_6,
                     param_7,bVar6,param_9,param_10,(char)param_11,1,param_12,param_14,param_15);
      }
    }
  }
  else if ((uVar2 == 0x8000) &&
          (uVar1 = FUN_8027001c(sVar5,uVar1,param_3,param_1,param_4,param_5,param_6,param_7,bVar6,
                                param_9,param_10,param_11,1,param_12,param_14,param_15),
          uVar1 != 0xffffffff)) {
    uVar1 = FUN_80279c00(uVar1);
    while (uVar1 != 0xffffffff) {
      iVar4 = (uVar1 & 0xff) * 0x404;
      *(undefined *)(DAT_803deee8 + iVar4 + 0x11c) = 0;
      uVar1 = *(uint *)(DAT_803deee8 + iVar4 + 0xec);
    }
  }
  return;
}

