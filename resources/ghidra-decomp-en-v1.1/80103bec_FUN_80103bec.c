// Function: FUN_80103bec
// Entry: 80103bec
// Size: 496 bytes

void FUN_80103bec(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  ushort uVar5;
  undefined2 local_28;
  undefined local_26;
  undefined local_25;
  undefined4 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  longlong local_18;
  
  if (*(int *)(param_2 + 0xc0) == 0) {
    uVar2 = FUN_80014e9c(0);
    if ((((*(int *)(param_1 + 0x124) == 0) ||
         (((sVar1 = *(short *)(*(int *)(param_1 + 0x124) + 0x44), sVar1 != 0x1c && (sVar1 != 0x2a))
          || (*(short *)(param_2 + 0x44) != 1)))) ||
        ((iVar3 = FUN_80296e60(param_2), iVar3 == 0 || (uVar4 = FUN_8029636c(param_2), uVar4 == 0)))
        ) && ((*(byte *)(param_1 + 0x141) & 2) == 0)) {
      if ((((uVar2 & 0x10) == 0) || (*(short *)(param_2 + 0x44) != 1)) ||
         (iVar3 = FUN_80296a14(param_2), iVar3 == 0)) {
        iVar3 = FUN_80080490();
        if (((iVar3 == 0) && (uVar5 = FUN_80014dc8(0), (uVar5 & 0x40) != 0)) &&
           ((*(ushort *)(param_1 + 6) & 4) == 0)) {
          local_28 = 5;
          local_26 = 1;
          local_25 = 1;
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x43,1,0,4,&local_28,0,0xff);
        }
      }
      else {
        local_24 = *DAT_803de1a8;
        local_20 = DAT_803de1a8[2];
        local_18 = (longlong)(int)(float)DAT_803de1a8[0x23];
        local_1c = (undefined2)(int)(float)DAT_803de1a8[0x23];
        FUN_80101c10(0);
        (**(code **)(*DAT_803dd6d0 + 0x1c))(0x44,1,0,0xc,&local_24,0xf,0xfe);
      }
    }
    else {
      FUN_80101c10(1);
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
    }
  }
  return;
}

