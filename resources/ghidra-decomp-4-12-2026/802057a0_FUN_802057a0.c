// Function: FUN_802057a0
// Entry: 802057a0
// Size: 676 bytes

void FUN_802057a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  
  iVar2 = FUN_80286840();
  iVar8 = *(int *)(iVar2 + 0xb8);
  iVar7 = *(int *)(iVar2 + 0x4c);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    sVar1 = *(short *)(iVar8 + 8);
    if (sVar1 == 10) {
      if (*(char *)(param_11 + iVar6 + 0x81) == '\x14') {
        if (*(int *)(iVar7 + 0x14) == 0x49de8) {
          *(byte *)(iVar8 + 0xf) = *(byte *)(iVar8 + 0xf) & 0x7f | 0x80;
        }
        else {
          cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
          if ((cVar4 == '\x01') ||
             (cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac)),
             cVar4 == '\x02')) {
            FUN_80043604(0,0,1);
            uVar3 = FUN_8004832c(0x32);
            FUN_80043658(uVar3,0);
            iVar5 = *DAT_803dd72c;
            uVar9 = (**(code **)(iVar5 + 0x44))(0x32,2);
            FUN_80055464(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x73,'\0',
                         iVar5,param_12,param_13,param_14,param_15,param_16);
          }
        }
      }
    }
    else if (((sVar1 < 10) && (sVar1 == 1)) && (*(char *)(param_11 + iVar6 + 0x81) == '\x01')) {
      cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
      if (cVar4 == '\x01') {
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
        param_12 = *DAT_803dd72c;
        (**(code **)(param_12 + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
      }
      else {
        cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
        if (cVar4 == '\x02') {
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
          param_12 = *DAT_803dd72c;
          (**(code **)(param_12 + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
        }
      }
    }
    *(undefined *)(param_11 + iVar6 + 0x81) = 0;
  }
  FUN_8028688c();
  return;
}

