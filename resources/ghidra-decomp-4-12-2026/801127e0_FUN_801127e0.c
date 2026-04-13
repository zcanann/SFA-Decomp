// Function: FUN_801127e0
// Entry: 801127e0
// Size: 412 bytes

void FUN_801127e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  short sVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  uint local_30;
  uint local_2c;
  uint local_28 [10];
  
  uVar9 = FUN_80286834();
  uVar1 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar3 = (int)uVar9;
  local_30 = 0;
  puVar4 = param_13;
  uVar5 = param_14;
  uVar6 = param_15;
  uVar7 = param_16;
  uVar9 = extraout_f1;
LAB_80112944:
  do {
    while( true ) {
      while( true ) {
        iVar2 = FUN_800375e4(uVar1,&local_2c,local_28,&local_30);
        if (iVar2 == 0) goto LAB_80112964;
        if (local_2c != 0xb) break;
        *(char *)(iVar3 + 0x34e) = (char)local_30;
      }
      sVar8 = (short)param_15;
      if ((int)local_2c < 0xb) break;
      if (local_2c == 0xe0000) {
        if (local_28[0] == *(uint *)(iVar3 + 0x2d0)) {
          *(short *)(iVar3 + 0x270) = (short)param_14;
          *(undefined4 *)(iVar3 + 0x2d0) = 0;
          *(undefined *)(iVar3 + 0x349) = 0;
        }
      }
      else if (((int)local_2c < 0xe0000) && (local_2c == 0xa0001)) {
LAB_801128c4:
        if (*(short *)(iVar3 + 0x270) != sVar8) {
          FUN_8011301c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,iVar3,
                       param_11,param_12,param_13,param_14,param_16,0,'\x01');
          *(short *)(iVar3 + 0x270) = sVar8;
          *(undefined *)(iVar3 + 0x349) = 0;
          *(uint *)(iVar3 + 0x2d0) = local_28[0];
          goto LAB_80112964;
        }
      }
    }
    if (local_2c != 3) {
      if ((int)local_2c < 3) {
        if (local_2c == 1) goto LAB_801128c4;
      }
      else if ((int)local_2c < 5) {
        FUN_800379bc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_28[0],5,
                     uVar1,0,puVar4,uVar5,uVar6,uVar7);
      }
      goto LAB_80112944;
    }
    if (*(short *)(iVar3 + 0x270) == sVar8) {
      *(undefined *)(iVar3 + 0x349) = 0;
      *(undefined4 *)(iVar3 + 0x2d0) = 0;
      *(short *)(iVar3 + 0x270) = (short)param_14;
LAB_80112964:
      FUN_80286880();
      return;
    }
  } while( true );
}

