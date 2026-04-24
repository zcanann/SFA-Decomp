// Function: FUN_8011ae24
// Entry: 8011ae24
// Size: 1328 bytes

int FUN_8011ae24(void)

{
  char cVar1;
  byte bVar6;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined auStack40 [32];
  
  cVar1 = DAT_803dd6cf;
  bVar6 = DAT_803db410;
  if (3 < DAT_803db410) {
    bVar6 = 3;
  }
  if ('\0' < DAT_803dd6cf) {
    DAT_803dd6cf = DAT_803dd6cf - bVar6;
  }
  iVar2 = (**(code **)(*DAT_803dca4c + 0x14))();
  if (iVar2 == 0) {
    (**(code **)(*DAT_803dcaa0 + 0x34))();
    DAT_803dd6ce = 4;
  }
  if ((DAT_803dd6cd == '\0') && (DAT_803dd6cc == '\0')) {
    if (DAT_803db9fb == '\x03') {
      uVar4 = FUN_80014e70(0);
      if ((uVar4 & 0x100) == 0) {
        if ((uVar4 & 0x200) != 0) {
          (**(code **)(*DAT_803dca4c + 8))(0x14,5);
          DAT_803dd6cf = '#';
          DAT_803dd6cc = '\x01';
        }
      }
      else {
        FUN_8011a4e8();
      }
    }
    else {
      iVar2 = (**(code **)(*DAT_803dcaa0 + 0xc))();
      iVar5 = (**(code **)(*DAT_803dcaa0 + 0x14))();
      if (iVar5 != DAT_803dd6c0) {
        FUN_8000bb18(0,0xfc);
      }
      DAT_803dd6c0 = iVar5;
      if (DAT_803dd6b8 != 0) {
        (**(code **)(*DAT_803dcaa4 + 0x14))();
      }
      if ((iVar2 != -1) || (DAT_803db9fb == '\0')) {
        if (DAT_803db9fb == '\x02') {
          if (iVar2 == 0) {
            FUN_8000bb18(0,0x419);
            DAT_803dd6a4 = (undefined)iVar5;
            if (DAT_803db9fb != -1) {
              (**(code **)(*DAT_803dcaa0 + 8))();
            }
            DAT_803db9fb = '\x01';
            *(ushort *)(PTR_DAT_8031a7c8 + 0x16) = *(ushort *)(PTR_DAT_8031a7c8 + 0x16) & 0xbfff;
            PTR_DAT_8031a7c8[0x56] = 0;
            *(undefined2 *)(PTR_DAT_8031a7c8 + 0x3c) = 0x3d6;
            DAT_803dd6c5 = 0;
            (**(code **)(*DAT_803dcaa0 + 4))
                      (PTR_DAT_8031a7c8,DAT_8031a7cc,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
            (**(code **)(*DAT_803dcaa0 + 0x18))(0);
            DAT_803dd6bc = 0;
            DAT_803dd6bd = 0;
            DAT_803dd6be = 0;
            DAT_803dd6ce = 2;
          }
          else if (iVar2 == 1) {
            DAT_803dd6cd = '\x01';
            (**(code **)(*DAT_803dca4c + 8))(0x14,5);
            (**(code **)(*DAT_803dca70 + 0x1c))(0);
            (**(code **)(*DAT_803dca70 + 0x1c))(1);
            (**(code **)(*DAT_803dca70 + 0x1c))(2);
            (**(code **)(*DAT_803dca70 + 0x1c))(3);
            DAT_803dd6cf = '#';
          }
        }
        else if (DAT_803db9fb < '\x02') {
          if (DAT_803db9fb == '\0') {
            FUN_8011a280(iVar2,iVar5);
          }
          else if (-1 < DAT_803db9fb) {
            FUN_8011a0dc(iVar2,iVar5);
          }
        }
        else if (DAT_803db9fb == '\x04') {
          FUN_80119fac(iVar2,iVar5);
        }
      }
    }
    if (DAT_803db9fb == '\x01') {
      FUN_80119c20();
    }
    iVar2 = 0;
  }
  else {
    if (((cVar1 < '\r') || ('\f' < DAT_803dd6cf)) && (DAT_803dd6cf < '\x01')) {
      if (DAT_803dd6cd == '\0') {
        FUN_8011a914(0);
        DAT_803db424 = -2;
        FUN_80014948(4);
      }
      else {
        FUN_8011611c();
        if (DAT_803db424 == '\0') {
          FUN_800e8abc(0,0xffffffff);
        }
        else {
          FUN_800e87cc(DAT_803dd6a4);
        }
        FUN_8011a914(1);
        FUN_801368d4();
        uVar3 = FUN_80023834(0);
        FUN_800437bc(0x3d,0x20000000);
        FUN_80023834(uVar3);
        FUN_8000a518(0xbe,0);
        FUN_8000a518(0xc1,0);
        if (DAT_803dd6c4 != 0) {
          FUN_800e8abc(&DAT_803dba18,DAT_803dd6a4);
          (**(code **)(*DAT_803dcaac + 0x78))(1);
          iVar2 = (**(code **)(*DAT_803dcaac + 0x90))();
          *(undefined *)(iVar2 + 0xe) = 0xff;
        }
        if (DAT_803dd6c4 < 2) {
          FUN_80296b70(0);
        }
        else {
          FUN_8028f688(auStack40,s__savegame_save_d_bin_8031a864);
          iVar2 = FUN_80015ab4(auStack40,0,0);
          if (iVar2 != 0) {
            FUN_80003494(DAT_803dd498,iVar2,0x6ec);
          }
        }
        (**(code **)(*DAT_803dcaac + 0x20))();
      }
    }
    iVar2 = (uint)((uint)(int)DAT_803dd6cf < 0xd) - ((int)DAT_803dd6cf >> 0x1f);
  }
  return iVar2;
}

