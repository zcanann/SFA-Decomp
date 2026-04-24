// Function: FUN_80103950
// Entry: 80103950
// Size: 496 bytes

void FUN_80103950(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  undefined2 local_28;
  undefined local_26;
  undefined local_25;
  undefined4 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  longlong local_18;
  
  if (*(int *)(param_2 + 0xc0) == 0) {
    uVar2 = FUN_80014e70(0);
    if ((((*(int *)(param_1 + 0x124) == 0) ||
         (((sVar1 = *(short *)(*(int *)(param_1 + 0x124) + 0x44), sVar1 != 0x1c && (sVar1 != 0x2a))
          || (*(short *)(param_2 + 0x44) != 1)))) ||
        ((iVar3 = FUN_80296700(param_2), iVar3 == 0 || (iVar3 = FUN_80295c0c(param_2), iVar3 == 0)))
        ) && ((*(byte *)(param_1 + 0x141) & 2) == 0)) {
      if ((((uVar2 & 0x10) == 0) || (*(short *)(param_2 + 0x44) != 1)) ||
         (iVar3 = FUN_802962b4(param_2), iVar3 == 0)) {
        iVar3 = FUN_80080204();
        if (((iVar3 == 0) && (uVar2 = FUN_80014d9c(0), (uVar2 & 0x40) != 0)) &&
           ((*(ushort *)(param_1 + 6) & 4) == 0)) {
          local_28 = 5;
          local_26 = 1;
          local_25 = 1;
          (**(code **)(*DAT_803dca50 + 0x1c))(0x43,1,0,4,&local_28,0,0xff);
        }
      }
      else {
        local_24 = *DAT_803dd530;
        local_20 = DAT_803dd530[2];
        local_18 = (longlong)(int)(float)DAT_803dd530[0x23];
        local_1c = (undefined2)(int)(float)DAT_803dd530[0x23];
        FUN_80101974(0);
        (**(code **)(*DAT_803dca50 + 0x1c))(0x44,1,0,0xc,&local_24,0xf,0xfe);
      }
    }
    else {
      FUN_80101974(1);
      (**(code **)(*DAT_803dca50 + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
    }
  }
  return;
}

