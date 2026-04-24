// Function: FUN_802107ac
// Entry: 802107ac
// Size: 1060 bytes

void FUN_802107ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 uint *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  byte bVar2;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  int *piVar8;
  undefined8 uVar9;
  uint local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined2 local_4c;
  float local_48;
  float local_44;
  float local_40;
  uint local_3c [4];
  uint local_2c [7];
  
  piVar8 = *(int **)(param_9 + 0x5c);
  if ((*(char *)((int)piVar8 + 0xa1) != '\0') && ((*(byte *)((int)piVar8 + 0xaa) >> 6 & 1) != 0)) {
    piVar8[0x2b] = (int)FLOAT_803e7388;
  }
  *(undefined *)((int)piVar8 + 0xa1) = 0;
  *(undefined *)(piVar8 + 0x28) = 0xff;
  cVar1 = *(char *)(piVar8 + 0x29);
  if (cVar1 < '\0') {
    if (cVar1 < -10) {
      param_9[3] = param_9[3] | 0x4000;
      *(ushort *)(*piVar8 + 6) = *(ushort *)(*piVar8 + 6) | 0x4000;
      FUN_80035ff8((int)param_9);
      FUN_80035ff8(*piVar8);
    }
    else {
      *(char *)(piVar8 + 0x29) = cVar1 + -1;
    }
  }
  else {
    uVar9 = FUN_80036018((int)param_9);
    if (*piVar8 != 0) {
      uVar9 = FUN_80036018(*piVar8);
    }
    local_54 = DAT_802c2cc0;
    local_50 = DAT_802c2cc4;
    local_4c = DAT_802c2cc8;
    if (*(char *)((int)piVar8 + 0xa2) != *(char *)((int)piVar8 + 0xa3)) {
      if (*(int *)(param_9 + 100) != 0) {
        uVar9 = FUN_8002cc9c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 100));
        param_9[100] = 0;
        param_9[0x65] = 0;
        *(undefined *)((int)param_9 + 0xeb) = 0;
      }
      if (('\0' < *(char *)((int)piVar8 + 0xa2)) && (uVar3 = FUN_8002e144(), (uVar3 & 0xff) != 0)) {
        puVar4 = FUN_8002becc(0x18,*(undefined2 *)
                                    ((int)&local_54 + *(char *)((int)piVar8 + 0xa2) * 2));
        param_11 = (uint)*(char *)(param_9 + 0x56);
        param_12 = 0xffffffff;
        param_13 = *(uint **)(param_9 + 0x18);
        uVar5 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,4,
                             *(char *)(param_9 + 0x56),0xffffffff,param_13,param_14,param_15,
                             param_16);
        *(undefined4 *)(param_9 + 100) = uVar5;
        *(undefined *)((int)param_9 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar8 + 0xa3) = *(undefined *)((int)piVar8 + 0xa2);
    }
    if (*piVar8 == 0) {
      puVar6 = FUN_80037048(10,(int *)&local_58);
      iVar7 = FUN_80080284((int *)&DAT_8032af68,6,(int)(short)param_9[0x23]);
      for (param_11 = 0; (int)param_11 < (int)local_58; param_11 = param_11 + 1) {
        if (iVar7 == *(short *)(puVar6[param_11] + 0x46)) {
          *piVar8 = puVar6[param_11];
          param_11 = local_58;
        }
      }
    }
    uVar3 = FUN_80020078((int)*(short *)piVar8[1]);
    if (uVar3 != 0) {
      if ((((*piVar8 != 0) && (*(char *)(piVar8 + 0x29) != '\0')) &&
          ((int)(short)param_9[0x50] == (uint)*(ushort *)(piVar8 + 0x2a))) &&
         ((uVar3 = FUN_801ed02c(*piVar8), uVar3 != 0 &&
          (iVar7 = FUN_80080434((float *)(piVar8 + 0x26)), iVar7 != 0)))) {
        uVar3 = FUN_80022264(0,1);
        piVar8[0x25] = *(ushort *)(piVar8 + 0x2a) + 5;
        iVar7 = FUN_8002bac4();
        iVar7 = FUN_800386e0(param_9,iVar7,(float *)0x0);
        if (((short)iVar7 < 0) && (param_9[0x23] != 0x389)) {
          uVar9 = FUN_8003042c((double)FLOAT_803e7388,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,param_9,*(ushort *)(piVar8 + 0x2a) + 5,0,param_12,
                               param_13,param_14,param_15,param_16);
          param_11 = uVar3 & 0xff;
          param_12 = 0;
          FUN_8020f88c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar8,param_9
                       ,param_11,0);
        }
        else {
          uVar9 = FUN_8003042c((double)FLOAT_803e7388,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,param_9,*(ushort *)(piVar8 + 0x2a) + 6,0,param_12,
                               param_13,param_14,param_15,param_16);
          param_11 = uVar3 & 0xff;
          param_12 = 2;
          FUN_8020f88c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar8,param_9
                       ,param_11,2);
        }
        iVar7 = FUN_801ecff4(*piVar8);
        FUN_80080404((float *)(piVar8 + 0x26),(short)*(undefined4 *)(&DAT_8032af94 + iVar7 * 4));
      }
      if (*piVar8 != 0) {
        FUN_8020f9fc(param_9,*piVar8,param_11,param_12,param_13,param_14,param_15,param_16);
      }
      uVar3 = FUN_8008038c(300);
      if (uVar3 != 0) {
        FUN_8000bb38((uint)param_9,0x2e5);
      }
      if (*(char *)(piVar8 + 0x29) < 4) {
        local_2c[0] = DAT_802c2ca0;
        local_2c[1] = DAT_802c2ca4;
        local_2c[2] = DAT_802c2ca8;
        local_2c[3] = DAT_802c2cac;
        local_3c[0] = DAT_802c2cb0;
        local_3c[1] = DAT_802c2cb4;
        local_3c[2] = DAT_802c2cb8;
        local_3c[3] = DAT_802c2cbc;
        iVar7 = 3 - *(char *)(piVar8 + 0x29);
        bVar2 = *(byte *)((int)piVar8 + 0xa6);
        *(byte *)((int)piVar8 + 0xa6) = bVar2 + 1;
        if ((uint)bVar2 != ((int)(uint)bVar2 / DAT_803dce88) * DAT_803dce88) {
          local_48 = FLOAT_803e7388;
          local_44 = FLOAT_803dce84;
          local_40 = FLOAT_803e7388;
          FUN_80098da4(param_9,local_2c[iVar7] & 0xff,local_3c[iVar7] & 0xff,0,&local_48);
        }
      }
    }
  }
  return;
}

