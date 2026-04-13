// Function: FUN_8011b0fc
// Entry: 8011b0fc
// Size: 1340 bytes

int FUN_8011b0fc(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar5;
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  char cVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  char acStack_28 [32];
  
  cVar6 = DAT_803de34f;
  bVar5 = DAT_803dc070;
  if (3 < DAT_803dc070) {
    bVar5 = 3;
  }
  if ('\0' < DAT_803de34f) {
    DAT_803de34f = DAT_803de34f - bVar5;
  }
  iVar1 = (**(code **)(*DAT_803dd6cc + 0x14))();
  if (iVar1 == 0) {
    (**(code **)(*DAT_803dd720 + 0x34))();
    DAT_803de34e = 4;
  }
  if ((DAT_803de34d == '\0') && (DAT_803de34c == '\0')) {
    if (DAT_803dc65b == '\x03') {
      uVar3 = FUN_80014e9c(0);
      if ((uVar3 & 0x100) == 0) {
        if ((uVar3 & 0x200) != 0) {
          (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
          DAT_803de34f = '#';
          DAT_803de34c = '\x01';
        }
      }
      else {
        FUN_8011a790();
      }
    }
    else {
      iVar1 = (**(code **)(*DAT_803dd720 + 0xc))();
      iVar4 = (**(code **)(*DAT_803dd720 + 0x14))();
      uVar7 = extraout_f1_00;
      if (iVar4 != DAT_803de340) {
        uVar7 = FUN_8000bb38(0,0xfc);
      }
      DAT_803de340 = iVar4;
      if (DAT_803de338 != 0) {
        uVar7 = (**(code **)(*DAT_803dd724 + 0x14))();
      }
      if ((iVar1 != -1) || (DAT_803dc65b == '\0')) {
        cVar6 = (char)iVar4;
        if (DAT_803dc65b == '\x02') {
          if (iVar1 == 0) {
            FUN_8000bb38(0,0x419);
            DAT_803de324 = cVar6;
            if (DAT_803dc65b != -1) {
              (**(code **)(*DAT_803dd720 + 8))();
            }
            DAT_803dc65b = '\x01';
            *(ushort *)(PTR_DAT_8031b418 + 0x16) = *(ushort *)(PTR_DAT_8031b418 + 0x16) & 0xbfff;
            PTR_DAT_8031b418[0x56] = 0;
            *(undefined2 *)(PTR_DAT_8031b418 + 0x3c) = 0x3d6;
            DAT_803de345 = 0;
            (**(code **)(*DAT_803dd720 + 4))
                      (PTR_DAT_8031b418,DAT_8031b41c,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
            (**(code **)(*DAT_803dd720 + 0x18))(0);
            DAT_803de33c = 0;
            DAT_803de33d = 0;
            DAT_803de33e = 0;
            DAT_803de34e = 2;
          }
          else if (iVar1 == 1) {
            DAT_803de34d = '\x01';
            (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(0);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(1);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(2);
            (**(code **)(*DAT_803dd6f0 + 0x1c))(3);
            DAT_803de34f = '#';
          }
        }
        else if (DAT_803dc65b < '\x02') {
          if (DAT_803dc65b == '\0') {
            FUN_8011a528(iVar1,cVar6);
          }
          else if (-1 < DAT_803dc65b) {
            FUN_8011a384(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar4);
          }
        }
        else if (DAT_803dc65b == '\x04') {
          FUN_8011a254(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,cVar6);
        }
      }
    }
    if (DAT_803dc65b == '\x01') {
      FUN_80119ec8();
    }
    iVar1 = 0;
  }
  else {
    if (((cVar6 < '\r') || ('\f' < DAT_803de34f)) && (DAT_803de34f < '\x01')) {
      if (DAT_803de34d == '\0') {
        FUN_8011abbc(0);
        DAT_803dc084 = -2;
        FUN_80014974(4);
      }
      else {
        uVar7 = FUN_801163b8();
        if (DAT_803dc084 == '\0') {
          FUN_800e8d40(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        else {
          FUN_800e8a50(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de324);
        }
        FUN_8011abbc(1);
        uVar7 = FUN_80136c5c();
        uVar2 = FUN_800238f8(0);
        uVar7 = FUN_80043938(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_800238f8(uVar2);
        FUN_8000a538((int *)0xbe,0);
        FUN_8000a538((int *)0xc1,0);
        if (DAT_803de344 != 0) {
          FUN_800e8d40(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          (**(code **)(*DAT_803dd72c + 0x78))(1);
          iVar1 = (**(code **)(*DAT_803dd72c + 0x90))();
          *(undefined *)(iVar1 + 0xe) = 0xff;
          uVar7 = extraout_f1;
        }
        if (DAT_803de344 < 2) {
          FUN_802972d0(0);
        }
        else {
          uVar7 = FUN_8028fde8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               (int)acStack_28,s__savegame_save_d_bin_8031b4b4,(uint)DAT_803de344,
                               in_r6,in_r7,in_r8,in_r9,in_r10);
          uVar3 = FUN_80015aec(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               acStack_28,(int *)0x0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
          if (uVar3 != 0) {
            FUN_80003494(DAT_803de110,uVar3,0x6ec);
            FUN_800238c4(uVar3);
          }
        }
        (**(code **)(*DAT_803dd72c + 0x20))();
      }
    }
    iVar1 = (uint)((uint)(int)DAT_803de34f < 0xd) - ((int)DAT_803de34f >> 0x1f);
  }
  return iVar1;
}

