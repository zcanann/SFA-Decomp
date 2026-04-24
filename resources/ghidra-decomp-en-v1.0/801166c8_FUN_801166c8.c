// Function: FUN_801166c8
// Entry: 801166c8
// Size: 2124 bytes

/* WARNING: Removing unreachable block (ram,0x80116e90) */

int FUN_801166c8(void)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  char cVar5;
  byte bVar6;
  double dVar7;
  char local_18;
  char local_17 [11];
  
  cVar2 = DAT_803dd651;
  bVar6 = DAT_803db410;
  if (DAT_803db424 == -2) {
    iVar3 = FUN_800e8508();
    if ((iVar3 == 0) && (DAT_803db424 != '\0')) {
      FUN_8007dd04(1);
    }
    FUN_800e7f44();
    if (DAT_803db424 == -2) {
      DAT_803db424 = '\x01';
    }
  }
  if ((DAT_803dd61a == '\0') && (DAT_803dd648 == 0)) {
    FUN_8011611c();
    FUN_80014948(1);
    FUN_8001fee4();
    FUN_801368d4();
    uVar4 = FUN_80023834(0);
    FUN_800437bc(0x3d,0x20000000);
    FUN_80023834(uVar4);
    FUN_800e866c();
    iVar3 = 0;
  }
  else {
    FUN_8005cea8(0);
    FUN_8005cdf8(0);
    cVar5 = FUN_80134bbc();
    if (cVar5 == '\0') {
      if (DAT_803dd648 != 0) {
        DAT_803dd648 = DAT_803dd648 + -1;
      }
      if (DAT_803dd619 != '\0') {
        FUN_80116224();
      }
      if (((DAT_803dd64d != '\0') && (DAT_803dd64d = DAT_803dd64d + -1, DAT_803dd64d == '\0')) &&
         (DAT_803dd64f != '\0')) {
        FUN_80117b68(100,1000);
      }
      if ((DAT_803dd610 == 2) && (DAT_803dd698 = DAT_803dd698 + 1, 10 < DAT_803dd698)) {
        FUN_8011611c();
      }
      if (((DAT_803dd610 == 2) && (DAT_803dd64f != '\0')) && (DAT_803dd64e != '\0')) {
        iVar3 = FUN_80014e70(0);
        FUN_80014b78(0,local_17,&local_18);
        FUN_80014b3c(0,iVar3);
        FUN_80014b68(0);
        FUN_80014b58(0);
        bVar1 = false;
        if ((DAT_803dd680 == '\0') || (DAT_803dd648 != 0)) {
          if ((iVar3 != 0) || ((local_17[0] != '\0' || (local_18 != '\0')))) {
            bVar1 = true;
          }
        }
        else {
          bVar1 = true;
        }
        if (DAT_803dd680 != '\0') {
          DAT_803dd680 = '\0';
        }
        if (bVar1) {
          if (((iVar3 == 0) && (local_17[0] == '\0')) && (local_18 == '\0')) {
            DAT_803dd64c = '\x01';
            DAT_803dd648 = 0x3c;
          }
          else {
            DAT_803dd64c = '\x02';
          }
          (**(code **)(*DAT_803dcaa0 + 0x18))(0);
          DAT_803dd64f = '\0';
          (**(code **)(*DAT_803dca50 + 0x60))(0,1);
          if (DAT_803db424 == -1) {
            iVar3 = FUN_800e8508();
            if ((iVar3 == 0) && (DAT_803db424 != '\0')) {
              FUN_8007dd04(1);
            }
            FUN_800e7f44();
            if (DAT_803db424 == -1) {
              DAT_803db424 = '\x01';
            }
          }
        }
      }
      else if ((DAT_803dd64e != '\0') && (DAT_803dd64f == '\0')) {
        iVar3 = FUN_80014e70(0);
        FUN_80014b78(0,local_17,&local_18);
        if ((iVar3 == 0) && ((local_17[0] == '\0' && (local_18 == '\0')))) {
          if ((DAT_803dd680 != '\0') && (DAT_803dd680 = '\0', DAT_803dd648 == 0)) {
            DAT_803dd648 = 0x3c;
            DAT_803dd64c = DAT_803dd64c + -1;
            if (DAT_803dd64c == '\0') {
              DAT_803dd64c = '\x01';
              (**(code **)(*DAT_803dca50 + 0x60))(4,1);
              DAT_803dd64f = '\x01';
              DAT_803dd617 = -0x19;
            }
          }
        }
        else {
          DAT_803dd64c = '\x02';
        }
      }
      if (3 < bVar6) {
        bVar6 = 3;
      }
      if ('\0' < DAT_803dd651) {
        DAT_803dd651 = DAT_803dd651 - bVar6;
      }
      iVar3 = (**(code **)(*DAT_803dca50 + 0x10))();
      if (iVar3 == 0x57) {
        DAT_803dd64e = '\x01';
        if (DAT_803dd650 == '\0') {
          iVar3 = (**(code **)(*DAT_803dcaa0 + 0xc))();
          DAT_803dd614 = (**(code **)(*DAT_803dcaa0 + 0x14))();
          dVar7 = (double)FUN_801115e4();
          if ((((double)FLOAT_803e1d28 == dVar7) && (DAT_803dd616 < 0xff)) && (DAT_803dd64f == '\0')
             ) {
            DAT_803dd617 = '\x19';
            if (DAT_803dd614 == 0) {
              DAT_803dd618 = 1;
            }
            else {
              DAT_803dd618 = 0;
            }
          }
          else if (DAT_803dd615 != DAT_803dd614) {
            (**(code **)(*DAT_803dca50 + 0x60))(DAT_803dd614,1);
            FUN_8000bb18(0,0x37b);
            DAT_803dd617 = -0x19;
            DAT_803dd615 = DAT_803dd614;
            FUN_80130464(0);
          }
          if ((int)((uint)DAT_803dd616 + (int)DAT_803dd617) < 0xff) {
            if ((int)((uint)DAT_803dd616 + (int)DAT_803dd617) < 1) {
              if (DAT_803dd614 == 0) {
                DAT_8031a22a = DAT_8031a22a & 0xbfff;
              }
              else {
                DAT_8031a22a = DAT_8031a22a | 0x4000;
              }
              if (DAT_803dd614 == 1) {
                DAT_8031a266 = DAT_8031a266 & 0xbfff;
              }
              else {
                DAT_8031a266 = DAT_8031a266 | 0x4000;
              }
              if (DAT_803dd614 == 2) {
                DAT_8031a2a2 = DAT_8031a2a2 & 0xbfff;
              }
              else {
                DAT_8031a2a2 = DAT_8031a2a2 | 0x4000;
              }
              if (DAT_803dd614 == 3) {
                DAT_8031a2de = DAT_8031a2de & 0xbfff;
              }
              else {
                DAT_8031a2de = DAT_8031a2de | 0x4000;
              }
              (**(code **)(*DAT_803dcaa0 + 0x2c))(&DAT_8031a214);
              DAT_803dd616 = 0;
              DAT_803dd617 = '\0';
              if (DAT_803dd614 != 0) {
                DAT_803dd618 = 0;
              }
            }
            else {
              DAT_803dd616 = DAT_803dd616 + DAT_803dd617;
            }
          }
          else {
            DAT_803dd616 = 0xff;
            DAT_803dd617 = '\0';
            FUN_80130464(1);
          }
          if (DAT_803dd652 == '\0') {
            if (iVar3 == 1) {
              (**(code **)(*DAT_803dcaa0 + 8))();
              (**(code **)(*DAT_803dcaa0 + 4))(&DAT_8031a214,9,5,0,0,0,0x14,200,0xff,0xff,0xff,0xff)
              ;
              DAT_803dd652 = '\x01';
            }
          }
          else {
            FUN_801368c4((int)(char)DAT_803dd614);
            if ((iVar3 == 1) && (DAT_803dd616 == 0xff)) {
              FUN_801368a4(1);
              DAT_803dd651 = 1;
              FUN_80130464(1);
              FUN_8000bb18(0,0xff);
              if (DAT_803dd614 == 2) {
                DAT_803dd650 = '\a';
                DAT_803dd6f8 = 1;
              }
              else if (DAT_803dd614 < 2) {
                if (DAT_803dd614 == 0) {
                  DAT_803dd650 = '\x05';
                }
                else {
                  DAT_803dd650 = '\a';
                  DAT_803dd6f8 = 0;
                }
              }
              else if (DAT_803dd614 < 4) {
                DAT_803dd650 = '\a';
                DAT_803dd6f8 = 2;
              }
              return 0;
            }
            FUN_801368a4(0);
          }
          iVar3 = 0;
        }
        else {
          if (((cVar2 < '\r') || ('\f' < DAT_803dd651)) && (DAT_803dd651 < '\x01')) {
            (**(code **)(*DAT_803dcaa0 + 8))();
            FUN_8005cdd4(0);
            FUN_8013046c();
            FUN_80014948((int)DAT_803dd650);
          }
          iVar3 = (uint)((uint)(int)DAT_803dd651 < 0xd) - ((int)DAT_803dd651 >> 0x1f);
        }
      }
      else {
        DAT_803dd64e = '\0';
        iVar3 = 0;
      }
    }
    else {
      iVar3 = 0;
    }
  }
  return iVar3;
}

