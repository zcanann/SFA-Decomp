// Function: FUN_801f6d88
// Entry: 801f6d88
// Size: 752 bytes

void FUN_801f6d88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  iVar2 = FUN_80286840();
  iVar6 = *(int *)(iVar2 + 0xb8);
  uVar7 = extraout_f1;
  iVar3 = FUN_8002bac4();
  *(undefined *)(param_11 + 0x56) = 0;
  *(code **)(param_11 + 0xe8) = FUN_801f6b84;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    if (*(short *)(iVar6 + 8) == 0) {
      cVar1 = *(char *)(param_11 + iVar5 + 0x81);
      if (cVar1 != '\0') {
        *(char *)(iVar6 + 0xc) = cVar1;
        bVar4 = *(byte *)(param_11 + iVar5 + 0x81);
        if (bVar4 != 3) {
          if (bVar4 < 3) {
            if (bVar4 == 1) {
              uVar7 = FUN_800201ac(0x143,1);
            }
            else if (bVar4 != 0) {
              uVar7 = FUN_800201ac(0x143,0);
            }
          }
          else if (bVar4 == 5) {
            uVar7 = FUN_800201ac(0x21d,1);
          }
          else if (bVar4 < 5) {
            FUN_800201ac(0x21d,1);
            FUN_80296c78(iVar3,8,0);
            uVar7 = FUN_800201ac(0x277,1);
          }
        }
      }
    }
    else {
      bVar4 = *(byte *)(param_11 + iVar5 + 0x81);
      if (bVar4 == 0xb) {
        bVar4 = FUN_80089094(0);
        if (bVar4 != 0) {
          uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                               0x217,0,param_13,param_14,param_15,param_16);
          uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
                               iVar2,0x216,0,param_13,param_14,param_15,param_16);
          uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
                               iVar2,0x84,0,param_13,param_14,param_15,param_16);
          FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,iVar2,
                       0x8a,0,param_13,param_14,param_15,param_16);
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),4,0);
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),10,1);
          uVar7 = (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),0xb,1);
        }
      }
      else if (((bVar4 < 0xb) && (9 < bVar4)) && (bVar4 = FUN_80089094(0), bVar4 == 0)) {
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x22d
                             ,0,param_13,param_14,param_15,param_16);
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
                             iVar2,0x22c,0,param_13,param_14,param_15,param_16);
        uVar7 = FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
                             iVar2,0x229,0,param_13,param_14,param_15,param_16);
        FUN_80008b74(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,iVar2,0x22a
                     ,0,param_13,param_14,param_15,param_16);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),4,1);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),10,0);
        uVar7 = (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),0xb,0);
      }
    }
    *(undefined *)(param_11 + iVar5 + 0x81) = 0;
  }
  FUN_8028688c();
  return;
}

