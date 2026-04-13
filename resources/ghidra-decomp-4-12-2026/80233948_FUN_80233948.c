// Function: FUN_80233948
// Entry: 80233948
// Size: 1396 bytes

void FUN_80233948(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  undefined uStack_48;
  undefined local_47;
  undefined local_46;
  undefined local_45 [5];
  undefined4 local_40;
  uint uStack_3c;
  undefined8 local_38;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  psVar5 = *(short **)(param_9 + 0xb8);
  if (*(char *)((int)psVar5 + 0x15) == '\x01') {
    iVar2 = FUN_8022de2c();
    if (iVar2 == 0) {
      iVar2 = FUN_8002bac4();
    }
    dVar6 = (double)FUN_800217c8((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18));
    if (dVar6 < (double)FLOAT_803e7e80) {
      FUN_80125e88(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
      *(undefined *)((int)psVar5 + 0x15) = 0;
    }
  }
  bVar1 = *(byte *)(psVar5 + 10);
  if (bVar1 == 2) {
    *(undefined *)(param_9 + 0x36) = 0xff;
    if (*(int *)(psVar5 + 2) != 0) {
      FUN_8001db90(*(int *)(psVar5 + 2),local_45,&local_46,&local_47,&uStack_48);
      FUN_8001d7e0(*(int *)(psVar5 + 2),local_45[0],local_46,local_47,100);
    }
    iVar2 = FUN_80080434((float *)(psVar5 + 6));
    if ((iVar2 != 0) ||
       ((*(int *)(*(int *)(param_9 + 0x54) + 0x50) != 0 &&
        (iVar2 = FUN_8022de2c(), *(int *)(*(int *)(param_9 + 0x54) + 0x50) == iVar2)))) {
      FUN_800803f8((undefined4 *)(psVar5 + 6));
      FUN_80080404((float *)(psVar5 + 8),0x14);
      if (*(int *)(psVar5 + 2) != 0) {
        FUN_8001dc30((double)FLOAT_803e7e70,*(int *)(psVar5 + 2),'\0');
      }
      FUN_8009adfc((double)FLOAT_803e7e78,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,1,1,0,0,1);
      FUN_80035a6c(param_9,300);
      FUN_80035eec(param_9,5,1,0);
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
      FUN_80035f84(param_9);
      *(undefined *)(psVar5 + 10) = 3;
    }
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = FUN_8022de2c();
        if (iVar2 == 0) {
          iVar2 = FUN_8002bac4();
        }
        dVar6 = (double)FUN_800217c8((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18));
        if ((double)FLOAT_803e7e84 <= dVar6) {
          return;
        }
        piVar3 = FUN_8001f58c(param_9,'\x01');
        *(int **)(psVar5 + 2) = piVar3;
        if (*(int *)(psVar5 + 2) != 0) {
          FUN_8001dbf0(*(int *)(psVar5 + 2),2);
          dVar8 = (double)FLOAT_803e7e88;
          FUN_8001de4c((double)FLOAT_803e7e70,(double)FLOAT_803e7e70,dVar8,*(int **)(psVar5 + 2));
          FUN_8001dbb4(*(int *)(psVar5 + 2),0,0xff,0,0);
          FUN_8001db7c(*(int *)(psVar5 + 2),0,0,0,0);
          dVar6 = (double)FLOAT_803e7e8c;
          FUN_8001dcfc((double)FLOAT_803e7e88,dVar6,*(int *)(psVar5 + 2));
          FUN_8001d7f4((double)FLOAT_803e7e90,dVar6,dVar8,param_4,param_5,param_6,param_7,param_8,
                       *(undefined4 *)(psVar5 + 2),0,0,0xff,0,100,in_r9,in_r10);
          FUN_8001d7d8((double)FLOAT_803e7e88,*(int *)(psVar5 + 2));
        }
        FUN_80036018(param_9);
        FUN_80035f84(param_9);
        *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) & 0xbfff;
        *(undefined *)(psVar5 + 10) = 1;
        return;
      }
    }
    else {
      if (bVar1 == 4) {
        if (*(uint *)(psVar5 + 2) == 0) {
          return;
        }
        FUN_8001f448(*(uint *)(psVar5 + 2));
        psVar5[2] = 0;
        psVar5[3] = 0;
        return;
      }
      if (bVar1 < 4) {
        iVar2 = FUN_80080434((float *)(psVar5 + 8));
        if (iVar2 != 0) {
          FUN_80035ff8(param_9);
          *(undefined *)(psVar5 + 10) = 4;
        }
        goto LAB_80233d34;
      }
    }
    param_3 = (double)FLOAT_803e7e94;
    param_2 = (double)FLOAT_803dc074;
    uStack_3c = (uint)*(byte *)(param_9 + 0x36);
    local_40 = 0x43300000;
    iVar2 = (int)(param_3 * param_2 +
                 (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ea0));
    local_38 = (double)(longlong)iVar2;
    if (0xff < iVar2) {
      iVar2 = 0xff;
    }
    *(char *)(param_9 + 0x36) = (char)iVar2;
    iVar2 = FUN_8022de2c();
    if (iVar2 == 0) {
      iVar2 = FUN_8002bac4();
    }
    dVar6 = (double)FUN_800217c8((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18));
    if (dVar6 < (double)FLOAT_803e7e98) {
      if (*(int *)(psVar5 + 2) != 0) {
        FUN_8001dbb4(*(int *)(psVar5 + 2),0xff,0,0,0);
        FUN_8001d7e0(*(int *)(psVar5 + 2),0xff,0,0,100);
        FUN_8001d6e4(*(int *)(psVar5 + 2),2,10);
      }
      uVar7 = FUN_80080404((float *)(psVar5 + 6),0x3c);
      *(undefined *)(psVar5 + 10) = 2;
      if (*(char *)((int)psVar5 + 0x15) == '\x02') {
        uVar4 = FUN_80022264(0,1);
        if (uVar4 == 0) {
          FUN_80125e88(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xc);
        }
        else {
          FUN_80125e88(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xf);
        }
      }
    }
  }
LAB_80233d34:
  if ((*(char *)(psVar5 + 10) == '\x01') || (*(char *)(psVar5 + 10) == '\x02')) {
    iVar2 = FUN_80036974(param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if (iVar2 != 0) {
      iVar2 = FUN_8022de2c();
      uVar7 = FUN_8022dbe4(iVar2,10);
      if (*(char *)((int)psVar5 + 0x15) == '\x03') {
        FUN_80125e88(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xe);
      }
      if (*(int *)(psVar5 + 2) != 0) {
        FUN_8001dc30((double)FLOAT_803e7e70,*(int *)(psVar5 + 2),'\0');
      }
      FUN_8009adfc((double)FLOAT_803e7e74,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,0,0,0,0,1);
      FUN_80035ff8(param_9);
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
      FUN_80035f84(param_9);
      *(undefined *)(psVar5 + 10) = 4;
    }
    dVar6 = DOUBLE_803e7ea8;
    local_38 = (double)CONCAT44(0x43300000,(int)*psVar5 ^ 0x80000000);
    uStack_3c = (int)*(short *)(param_9 + 4) ^ 0x80000000;
    local_40 = 0x43300000;
    iVar2 = (int)(FLOAT_803dc074 * (float)(local_38 - DOUBLE_803e7ea8) +
                 (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ea8));
    local_30 = (longlong)iVar2;
    *(short *)(param_9 + 4) = (short)iVar2;
    uStack_24 = (int)*psVar5 ^ 0x80000000;
    local_28 = 0x43300000;
    uStack_1c = (int)*(short *)(param_9 + 2) ^ 0x80000000;
    local_20 = 0x43300000;
    iVar2 = (int)(FLOAT_803dc074 * (float)((double)CONCAT44(0x43300000,uStack_24) - dVar6) +
                 (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar6));
    local_18 = (longlong)iVar2;
    *(short *)(param_9 + 2) = (short)iVar2;
  }
  if ((*(int *)(psVar5 + 2) != 0) && (iVar2 = FUN_8001dc28(*(int *)(psVar5 + 2)), iVar2 != 0)) {
    FUN_8001d774(*(int *)(psVar5 + 2));
  }
  return;
}

