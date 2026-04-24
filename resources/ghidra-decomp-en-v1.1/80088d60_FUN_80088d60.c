// Function: FUN_80088d60
// Entry: 80088d60
// Size: 312 bytes

void FUN_80088d60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 byte param_9)

{
  short sVar1;
  ushort uVar2;
  char cVar3;
  int iVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar6;
  
  iVar4 = FUN_8002bac4();
  if ((((DAT_803dddb4 != 0) && (iVar4 != 0)) && ((DAT_803dddc0 & 8) != 0)) &&
     (uVar5 = FUN_80020078(0x3b0), uVar5 == 0)) {
    cVar3 = param_9 - 1;
    if (cVar3 < '\0') {
      cVar3 = '\x1b';
    }
    sVar1 = *(short *)(DAT_803dddb4 + (uint)param_9 * 2);
    if ((sVar1 < 1) || (*(short *)(DAT_803dddb4 + cVar3 * 2) != sVar1)) {
      uVar6 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                           iVar4,0x136,0,in_r7,in_r8,in_r9,in_r10);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,iVar4
                           ,0x137,0,in_r7,in_r8,in_r9,in_r10);
      param_1 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                             iVar4,0x143,0,in_r7,in_r8,in_r9,in_r10);
    }
    uVar2 = *(ushort *)(DAT_803dddb4 + (uint)param_9 * 2);
    if (0 < (short)uVar2) {
      if ((DAT_803dddc0 & 0x20) == 0) {
        FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,iVar4,
                     (uint)uVar2,0,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        FUN_80008b74(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,iVar4,
                     (uint)uVar2,0,in_r7,in_r8,in_r9,in_r10);
      }
    }
  }
  return;
}

