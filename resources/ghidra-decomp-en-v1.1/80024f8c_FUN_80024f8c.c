// Function: FUN_80024f8c
// Entry: 80024f8c
// Size: 1368 bytes

void FUN_80024f8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9,int param_10,undefined4 param_11,undefined4 param_12,uint *param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  char *local_48;
  uint local_44;
  uint uStack_40;
  char *local_3c;
  uint local_38;
  uint uStack_34;
  char *local_30;
  uint local_2c;
  uint uStack_28;
  char *local_24;
  uint local_20;
  uint auStack_1c [3];
  
  *(undefined2 *)(param_10 + 0x44) = 0;
  *(undefined2 *)(param_10 + 0x5e) = 0;
  *(undefined2 *)(param_10 + 0x58) = 0;
  *(undefined2 *)(param_10 + 0x5a) = 0;
  *(undefined2 *)(param_10 + 0x5c) = 0;
  fVar2 = FLOAT_803df4a8;
  *(float *)(param_10 + 0xc) = FLOAT_803df4a8;
  *(float *)(param_10 + 4) = fVar2;
  *(float *)(param_10 + 0x14) = fVar2;
  *(undefined *)(param_10 + 0x60) = 0;
  iVar6 = *param_9;
  if (*(short *)(iVar6 + 0xec) != 0) {
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      iVar6 = *(int *)(*(int *)(iVar6 + 100) + (uint)*(ushort *)(param_10 + 0x44) * 4);
    }
    else {
      iVar4 = *(int *)(param_10 + 0x1c);
      sVar1 = **(short **)(iVar6 + 0x6c);
      iVar5 = (int)sVar1;
      uVar3 = FUN_800431a4();
      if ((((uVar3 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar4 == 0) {
          iVar4 = FUN_80013c30(DAT_803dd7d0,iVar5,(uint)&local_24);
          if (iVar4 == 0) {
            uVar3 = *(uint *)(DAT_803dd7cc + iVar5 * 4);
            uVar7 = FUN_80046644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 0x30,0,uVar3,0,&local_20,iVar5,1,param_16);
            local_24 = (char *)FUN_80023d8c(local_20,10);
            param_13 = auStack_1c;
            param_15 = 0;
            FUN_80046644(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,local_24
                         ,uVar3,local_20,param_13,iVar5,0,param_16);
            *local_24 = '\x01';
            param_1 = FUN_80013d08(DAT_803dd7d0,sVar1,(uint)&local_24);
            param_14 = iVar5;
          }
          else {
            *local_24 = *local_24 + '\x01';
          }
        }
        else {
          param_1 = FUN_80028178(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 iVar6,iVar5,0,iVar4,param_13,param_14,param_15,param_16);
        }
      }
      iVar4 = *(int *)(param_10 + 0x20);
      sVar1 = **(short **)(iVar6 + 0x6c);
      iVar5 = (int)sVar1;
      uVar3 = FUN_800431a4();
      if ((((uVar3 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar4 == 0) {
          iVar4 = FUN_80013c30(DAT_803dd7d0,iVar5,(uint)&local_30);
          if (iVar4 == 0) {
            uVar3 = *(uint *)(DAT_803dd7cc + iVar5 * 4);
            uVar7 = FUN_80046644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 0x30,0,uVar3,0,&local_2c,iVar5,1,param_16);
            local_30 = (char *)FUN_80023d8c(local_2c,10);
            param_13 = &uStack_28;
            param_15 = 0;
            FUN_80046644(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,local_30
                         ,uVar3,local_2c,param_13,iVar5,0,param_16);
            *local_30 = '\x01';
            param_1 = FUN_80013d08(DAT_803dd7d0,sVar1,(uint)&local_30);
            param_14 = iVar5;
          }
          else {
            *local_30 = *local_30 + '\x01';
          }
        }
        else {
          param_1 = FUN_80028178(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 iVar6,iVar5,0,iVar4,param_13,param_14,param_15,param_16);
        }
      }
      iVar4 = *(int *)(param_10 + 0x24);
      sVar1 = **(short **)(iVar6 + 0x6c);
      iVar5 = (int)sVar1;
      uVar3 = FUN_800431a4();
      if ((((uVar3 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar4 == 0) {
          iVar4 = FUN_80013c30(DAT_803dd7d0,iVar5,(uint)&local_3c);
          if (iVar4 == 0) {
            uVar3 = *(uint *)(DAT_803dd7cc + iVar5 * 4);
            uVar7 = FUN_80046644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 0x30,0,uVar3,0,&local_38,iVar5,1,param_16);
            local_3c = (char *)FUN_80023d8c(local_38,10);
            param_13 = &uStack_34;
            param_15 = 0;
            FUN_80046644(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,local_3c
                         ,uVar3,local_38,param_13,iVar5,0,param_16);
            *local_3c = '\x01';
            param_1 = FUN_80013d08(DAT_803dd7d0,sVar1,(uint)&local_3c);
            param_14 = iVar5;
          }
          else {
            *local_3c = *local_3c + '\x01';
          }
        }
        else {
          param_1 = FUN_80028178(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 iVar6,iVar5,0,iVar4,param_13,param_14,param_15,param_16);
        }
      }
      iVar4 = *(int *)(param_10 + 0x28);
      sVar1 = **(short **)(iVar6 + 0x6c);
      iVar5 = (int)sVar1;
      uVar3 = FUN_800431a4();
      if ((((uVar3 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar4 == 0) {
          iVar6 = FUN_80013c30(DAT_803dd7d0,iVar5,(uint)&local_48);
          if (iVar6 == 0) {
            uVar3 = *(uint *)(DAT_803dd7cc + iVar5 * 4);
            uVar7 = FUN_80046644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 0x30,0,uVar3,0,&local_44,iVar5,1,param_16);
            local_48 = (char *)FUN_80023d8c(local_44,10);
            FUN_80046644(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,local_48
                         ,uVar3,local_44,&uStack_40,iVar5,0,param_16);
            *local_48 = '\x01';
            FUN_80013d08(DAT_803dd7d0,sVar1,(uint)&local_48);
          }
          else {
            *local_48 = *local_48 + '\x01';
          }
        }
        else {
          FUN_80028178(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar6,iVar5,0
                       ,iVar4,param_13,param_14,param_15,param_16);
        }
      }
      *(undefined2 *)(param_10 + 0x44) = 0;
      iVar6 = *(int *)(param_10 + (uint)*(ushort *)(param_10 + 0x44) * 4 + 0x1c) + 0x80;
    }
    *(int *)(param_10 + 0x34) = iVar6 + 6;
    *(byte *)(param_10 + 0x60) = *(byte *)(iVar6 + 1) & 0xf0;
    *(float *)(param_10 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_10 + 0x34) + 1)) -
                DOUBLE_803df4b0);
    if (*(char *)(param_10 + 0x60) == '\0') {
      *(float *)(param_10 + 0x14) = *(float *)(param_10 + 0x14) - FLOAT_803df498;
    }
    *(undefined *)(param_10 + 0x61) = *(undefined *)(param_10 + 0x60);
    *(undefined4 *)(param_10 + 0x38) = *(undefined4 *)(param_10 + 0x34);
    *(undefined2 *)(param_10 + 0x46) = *(undefined2 *)(param_10 + 0x44);
    *(undefined4 *)(param_10 + 8) = *(undefined4 *)(param_10 + 4);
    *(undefined4 *)(param_10 + 0x18) = *(undefined4 *)(param_10 + 0x14);
    *(undefined4 *)(param_10 + 0x10) = *(undefined4 *)(param_10 + 0xc);
    *(undefined4 *)(param_10 + 0x3c) = *(undefined4 *)(param_10 + 0x34);
    *(undefined2 *)(param_10 + 0x48) = *(undefined2 *)(param_10 + 0x44);
    *(undefined4 *)(param_10 + 0x40) = *(undefined4 *)(param_10 + 0x34);
    *(undefined2 *)(param_10 + 0x4a) = *(undefined2 *)(param_10 + 0x44);
  }
  return;
}

