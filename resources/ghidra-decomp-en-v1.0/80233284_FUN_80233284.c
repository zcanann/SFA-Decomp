// Function: FUN_80233284
// Entry: 80233284
// Size: 1396 bytes

void FUN_80233284(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  short *psVar4;
  double dVar5;
  undefined uStack72;
  undefined local_47;
  undefined local_46;
  undefined local_45 [5];
  undefined4 local_40;
  uint uStack60;
  double local_38;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  psVar4 = *(short **)(param_1 + 0xb8);
  if (*(char *)((int)psVar4 + 0x15) == '\x01') {
    iVar2 = FUN_8022d768();
    if (iVar2 == 0) {
      iVar2 = FUN_8002b9ec();
    }
    dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
    if (dVar5 < (double)FLOAT_803e71e8) {
      FUN_80125ba4(0xb);
      *(undefined *)((int)psVar4 + 0x15) = 0;
    }
  }
  bVar1 = *(byte *)(psVar4 + 10);
  if (bVar1 == 2) {
    *(undefined *)(param_1 + 0x36) = 0xff;
    if (*(int *)(psVar4 + 2) != 0) {
      FUN_8001dacc(*(int *)(psVar4 + 2),local_45,&local_46,&local_47,&uStack72);
      FUN_8001d71c(*(undefined4 *)(psVar4 + 2),local_45[0],local_46,local_47,100);
    }
    iVar2 = FUN_800801a8(psVar4 + 6);
    if ((iVar2 != 0) ||
       ((*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0 &&
        (iVar2 = FUN_8022d768(), *(int *)(*(int *)(param_1 + 0x54) + 0x50) == iVar2)))) {
      FUN_8008016c(psVar4 + 6);
      FUN_80080178(psVar4 + 8,0x14);
      if (*(int *)(psVar4 + 2) != 0) {
        FUN_8001db6c((double)FLOAT_803e71d8,*(int *)(psVar4 + 2),0);
      }
      FUN_8009ab70((double)FLOAT_803e71e0,param_1,1,0,1,1,0,0,1);
      FUN_80035974(param_1,300);
      FUN_80035df4(param_1,5,1,0);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_80035e8c(param_1);
      *(undefined *)(psVar4 + 10) = 3;
    }
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = FUN_8022d768();
        if (iVar2 == 0) {
          iVar2 = FUN_8002b9ec();
        }
        dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
        if ((double)FLOAT_803e71ec <= dVar5) {
          return;
        }
        uVar3 = FUN_8001f4c8(param_1,1);
        *(undefined4 *)(psVar4 + 2) = uVar3;
        if (*(int *)(psVar4 + 2) != 0) {
          FUN_8001db2c(*(int *)(psVar4 + 2),2);
          FUN_8001dd88((double)FLOAT_803e71d8,(double)FLOAT_803e71d8,(double)FLOAT_803e71f0,
                       *(undefined4 *)(psVar4 + 2));
          FUN_8001daf0(*(undefined4 *)(psVar4 + 2),0,0xff,0,0);
          FUN_8001dab8(*(undefined4 *)(psVar4 + 2),0,0,0,0);
          FUN_8001dc38((double)FLOAT_803e71f0,(double)FLOAT_803e71f4,*(undefined4 *)(psVar4 + 2));
          FUN_8001d730((double)FLOAT_803e71f8,*(undefined4 *)(psVar4 + 2),0,0,0xff,0,100);
          FUN_8001d714((double)FLOAT_803e71f0,*(undefined4 *)(psVar4 + 2));
        }
        FUN_80035f20(param_1);
        FUN_80035e8c(param_1);
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
        *(undefined *)(psVar4 + 10) = 1;
        return;
      }
    }
    else {
      if (bVar1 == 4) {
        if (*(int *)(psVar4 + 2) == 0) {
          return;
        }
        FUN_8001f384();
        *(undefined4 *)(psVar4 + 2) = 0;
        return;
      }
      if (bVar1 < 4) {
        iVar2 = FUN_800801a8(psVar4 + 8);
        if (iVar2 != 0) {
          FUN_80035f00(param_1);
          *(undefined *)(psVar4 + 10) = 4;
        }
        goto LAB_80233670;
      }
    }
    uStack60 = (uint)*(byte *)(param_1 + 0x36);
    local_40 = 0x43300000;
    iVar2 = (int)(FLOAT_803e71fc * FLOAT_803db414 +
                 (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7208));
    local_38 = (double)(longlong)iVar2;
    if (0xff < iVar2) {
      iVar2 = 0xff;
    }
    *(char *)(param_1 + 0x36) = (char)iVar2;
    iVar2 = FUN_8022d768();
    if (iVar2 == 0) {
      iVar2 = FUN_8002b9ec();
    }
    dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
    if (dVar5 < (double)FLOAT_803e7200) {
      if (*(int *)(psVar4 + 2) != 0) {
        FUN_8001daf0(*(int *)(psVar4 + 2),0xff,0,0,0);
        FUN_8001d71c(*(undefined4 *)(psVar4 + 2),0xff,0,0,100);
        FUN_8001d620(*(undefined4 *)(psVar4 + 2),2,10);
      }
      FUN_80080178(psVar4 + 6,0x3c);
      *(undefined *)(psVar4 + 10) = 2;
      if (*(char *)((int)psVar4 + 0x15) == '\x02') {
        iVar2 = FUN_800221a0(0,1);
        if (iVar2 == 0) {
          FUN_80125ba4(0xc);
        }
        else {
          FUN_80125ba4(0xf);
        }
      }
    }
  }
LAB_80233670:
  if ((*(char *)(psVar4 + 10) == '\x01') || (*(char *)(psVar4 + 10) == '\x02')) {
    iVar2 = FUN_8003687c(param_1,0,0,0);
    if (iVar2 != 0) {
      uVar3 = FUN_8022d768();
      FUN_8022d520(uVar3,10);
      if (*(char *)((int)psVar4 + 0x15) == '\x03') {
        FUN_80125ba4(0xe);
      }
      if (*(int *)(psVar4 + 2) != 0) {
        FUN_8001db6c((double)FLOAT_803e71d8,*(int *)(psVar4 + 2),0);
      }
      FUN_8009ab70((double)FLOAT_803e71dc,param_1,1,0,0,0,0,0,1);
      FUN_80035f00(param_1);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_80035e8c(param_1);
      *(undefined *)(psVar4 + 10) = 4;
    }
    dVar5 = DOUBLE_803e7210;
    local_38 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
    uStack60 = (int)*(short *)(param_1 + 4) ^ 0x80000000;
    local_40 = 0x43300000;
    iVar2 = (int)(FLOAT_803db414 * (float)(local_38 - DOUBLE_803e7210) +
                 (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7210));
    local_30 = (longlong)iVar2;
    *(short *)(param_1 + 4) = (short)iVar2;
    uStack36 = (int)*psVar4 ^ 0x80000000;
    local_28 = 0x43300000;
    uStack28 = (int)*(short *)(param_1 + 2) ^ 0x80000000;
    local_20 = 0x43300000;
    iVar2 = (int)(FLOAT_803db414 * (float)((double)CONCAT44(0x43300000,uStack36) - dVar5) +
                 (float)((double)CONCAT44(0x43300000,uStack28) - dVar5));
    local_18 = (longlong)iVar2;
    *(short *)(param_1 + 2) = (short)iVar2;
  }
  if ((*(int *)(psVar4 + 2) != 0) && (iVar2 = FUN_8001db64(), iVar2 != 0)) {
    FUN_8001d6b0(*(undefined4 *)(psVar4 + 2));
  }
  return;
}

