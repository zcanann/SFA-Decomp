// Function: FUN_80254acc
// Entry: 80254acc
// Size: 512 bytes

undefined4 FUN_80254acc(char *param_1,uint param_2)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  uint uVar5;
  uint local_20;
  undefined4 local_1c;
  
  if (DAT_803de0a0 == -0x5a00ffa6) {
    iVar3 = FUN_802544d0(DAT_803de098,DAT_803de09c,0);
    pcVar4 = param_1;
    if (iVar3 == 0) {
      uVar2 = 0;
    }
    else {
      for (; (uint)((int)pcVar4 - (int)param_1) < param_2; pcVar4 = pcVar4 + 1) {
        if (*pcVar4 == '\n') {
          *pcVar4 = '\r';
        }
      }
      local_1c = 0xa0010000;
      uVar2 = 0;
      while (param_2 != 0) {
        iVar3 = FUN_80253dd0(DAT_803de098,DAT_803de09c,3);
        if (iVar3 == 0) {
          uVar1 = 0xffffffff;
        }
        else {
          local_20 = 0x20010000;
          FUN_8025327c(DAT_803de098,&local_20,4,1,0);
          FUN_80253664(DAT_803de098);
          FUN_8025327c(DAT_803de098,&local_20,1,0,0);
          FUN_80253664(DAT_803de098);
          FUN_80253efc(DAT_803de098);
          uVar1 = 0x10 - (local_20 >> 0x18);
        }
        if ((int)uVar1 < 0) {
          uVar2 = 3;
          break;
        }
        if ((0xb < (int)uVar1) || (param_2 <= uVar1)) {
          iVar3 = FUN_80253dd0(DAT_803de098,DAT_803de09c,3);
          if (iVar3 == 0) {
            uVar2 = 3;
            break;
          }
          FUN_8025327c(DAT_803de098,&local_1c,4,1,0);
          FUN_80253664(DAT_803de098);
          for (; ((uVar1 != 0 && (param_2 != 0)) && ((3 < (int)uVar1 || (param_2 <= uVar1))));
              param_2 = param_2 - uVar5) {
            uVar5 = param_2;
            if (3 < param_2) {
              uVar5 = 4;
            }
            FUN_8025327c(DAT_803de098,param_1,uVar5,1,0);
            param_1 = param_1 + uVar5;
            uVar1 = uVar1 - uVar5;
            FUN_80253664(DAT_803de098);
          }
          FUN_80253efc(DAT_803de098);
        }
      }
      FUN_802545c4(DAT_803de098);
    }
  }
  else {
    uVar2 = 2;
  }
  return uVar2;
}

