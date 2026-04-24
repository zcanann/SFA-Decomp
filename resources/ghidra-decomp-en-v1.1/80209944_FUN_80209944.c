// Function: FUN_80209944
// Entry: 80209944
// Size: 1012 bytes

/* WARNING: Removing unreachable block (ram,0x80209b0c) */
/* WARNING: Removing unreachable block (ram,0x80209ce0) */
/* WARNING: Removing unreachable block (ram,0x802099c0) */

undefined4
FUN_80209944(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,int param_12,undefined4 param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)

{
  char cVar1;
  byte bVar4;
  undefined4 uVar2;
  uint uVar3;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  iVar5 = param_11;
  bVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
  uVar7 = FUN_8000da78(0,0x48b);
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    cVar1 = *(char *)(param_11 + iVar6 + 0x81);
    if (cVar1 == '\x01') {
      uVar7 = FUN_80041f34();
      if (bVar4 == 2) {
        FUN_80043070(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
        uVar2 = FUN_8004832c(0xb);
        FUN_80043658(uVar2,0);
      }
      else if (bVar4 < 2) {
        (**(code **)(*DAT_803dd72c + 0x50))(7,0,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,2,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,3,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,7,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,10,0);
        iVar5 = 0;
        param_12 = *DAT_803dd72c;
        (**(code **)(param_12 + 0x50))(10,7);
        uVar7 = FUN_800201ac(0x1ed,1);
        FUN_80043070(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x17);
        uVar2 = FUN_8004832c(0x17);
        FUN_80043658(uVar2,0);
      }
      else if (bVar4 < 4) {
        FUN_80043070(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,7);
        uVar2 = FUN_8004832c(7);
        FUN_80043658(uVar2,0);
      }
    }
    else if (cVar1 == '\x02') {
      if (bVar4 == 2) {
        FUN_800201ac(0x405,0);
        uVar3 = FUN_80020078(0xff);
        if (uVar3 == 0) {
          uVar3 = FUN_80020078(0xbfd);
          if (uVar3 == 0) {
            uVar3 = FUN_80020078(0xc6e);
            if (uVar3 != 0) {
              (**(code **)(*DAT_803dd72c + 0x44))(0xb,4);
              (**(code **)(*DAT_803dd72c + 0x50))(0xb,8,1);
              iVar5 = 1;
              param_12 = *DAT_803dd72c;
              uVar7 = (**(code **)(param_12 + 0x50))(0xb,9);
              FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x22,'\0',
                           iVar5,param_12,param_13,param_14,param_15,param_16);
            }
          }
          else {
            (**(code **)(*DAT_803dd72c + 0x44))(0xb,2);
            (**(code **)(*DAT_803dd72c + 0x50))(0xb,5,1);
            iVar5 = 1;
            param_12 = *DAT_803dd72c;
            uVar7 = (**(code **)(param_12 + 0x50))(0xb,6);
            FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x20,'\0',
                         iVar5,param_12,param_13,param_14,param_15,param_16);
          }
        }
        else {
          (**(code **)(*DAT_803dd72c + 0x44))(0xb,3);
          (**(code **)(*DAT_803dd72c + 0x50))(0xb,8,1);
          iVar5 = 1;
          param_12 = *DAT_803dd72c;
          uVar7 = (**(code **)(param_12 + 0x50))(0xb,9);
          FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x22,'\0',iVar5
                       ,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else if (bVar4 < 2) {
        FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,2,'\0',iVar5,
                     param_12,param_13,param_14,param_15,param_16);
      }
      else if (bVar4 < 4) {
        FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xf,'\0',iVar5,
                     param_12,param_13,param_14,param_15,param_16);
      }
      uVar7 = FUN_80014974(1);
    }
    else if (cVar1 == '\x03') {
      if (bVar4 == 3) {
        FUN_8004832c(0xb);
        uVar7 = FUN_80043938(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      else if (bVar4 < 3) {
        FUN_8004832c(7);
        uVar7 = FUN_80043938(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
  }
  return 0;
}

