// Function: FUN_8012bcb4
// Entry: 8012bcb4
// Size: 1292 bytes

void FUN_8012bcb4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char param_9)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  double dVar4;
  undefined8 uVar5;
  double dVar6;
  char local_18;
  char local_17 [11];
  
  iVar3 = -1;
  bVar2 = false;
  DAT_803de524 = FUN_80014e9c(0);
  if (DAT_803de3dc == 0) {
    dVar6 = (double)FLOAT_803de3e8;
    FLOAT_803de3e8 = (float)(dVar6 + (double)FLOAT_803dc074);
    dVar4 = (double)FLOAT_803de3e8;
    if (DAT_803de400 != 4) {
      if (DAT_803de400 < 4) {
        if (2 < DAT_803de400) {
          if (((double)FLOAT_803e2ce8 <= dVar4) && (dVar6 < (double)FLOAT_803e2ce8)) {
            if (DAT_803de456 == DAT_803de560) {
              FUN_8000d220(dVar4,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
            }
            else {
              FUN_8000d220(dVar4,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
            }
          }
          dVar4 = (double)FLOAT_803de3e8;
          if ((double)FLOAT_803e2e04 < dVar4) {
            FUN_80022264(0,3);
            FUN_8000d220(dVar4,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
            FLOAT_803de3e8 = FLOAT_803e2abc;
          }
        }
      }
      else if (((DAT_803de400 < 6) && ((double)FLOAT_803e2ce8 <= dVar4)) &&
              (dVar6 < (double)FLOAT_803e2ce8)) {
        FUN_80022264(0,3);
        FUN_8000d220(dVar4,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
        FLOAT_803de3e8 = FLOAT_803e2abc;
      }
    }
    if (FLOAT_803e2abc < FLOAT_803de3e4) {
      FUN_80014ba4(0,local_17,&local_18);
      if (local_18 == '\x01') {
        iVar3 = (int)(char)DAT_803de4a4[DAT_803de458 * 0x20 + 0xc];
      }
      if (local_18 == -1) {
        iVar3 = (int)(char)DAT_803de4a4[DAT_803de458 * 0x20 + 0xd];
      }
      if ((local_17[0] == -1) && (iVar3 == -1)) {
        iVar3 = (int)(char)DAT_803de4a4[DAT_803de458 * 0x20 + 0xe];
      }
      if ((local_17[0] == '\x01') && (iVar3 == -1)) {
        iVar3 = (int)(char)DAT_803de4a4[DAT_803de458 * 0x20 + 0xf];
      }
    }
    if (-1 < iVar3) {
      uVar5 = FUN_8000bb38(0,0x405);
      DAT_803de458 = iVar3;
      if ((*(short *)(DAT_803de4a4 + iVar3 * 0x20) < 0x4d) &&
         (0x4a < *(short *)(DAT_803de4a4 + iVar3 * 0x20))) {
        FUN_8000d220(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
    if (DAT_803de4a4 == &DAT_8031c9e0) {
      if ((&DAT_803a97a8)[*(short *)(&DAT_8031c9e0 + DAT_803de458 * 0x20)] != 0xbf0) {
        bVar2 = true;
      }
    }
    else {
      sVar1 = *(short *)(DAT_803de4a4 + DAT_803de458 * 0x20);
      if ((((-1 < sVar1) && (sVar1 != 0x25)) && (sVar1 != 0x24)) && (sVar1 != 0x49)) {
        bVar2 = true;
      }
    }
    if ((((DAT_803de524 & 0x100) != 0) && (DAT_803de4a4 != &DAT_8031c980)) &&
       (dVar4 = (double)FLOAT_803e2abc, dVar4 == (double)FLOAT_803de440)) {
      if (bVar2) {
        uVar5 = FUN_8000bb38(0,0x41b);
        if (DAT_803de400 != 4) {
          if (DAT_803de400 < 4) {
            if (2 < DAT_803de400) {
              FUN_80022264(0,1);
              FUN_8000d220(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
              FLOAT_803de3e8 = FLOAT_803e2abc;
            }
          }
          else if (DAT_803de400 < 6) {
            FUN_80022264(0,1);
            FUN_8000d220(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
            FLOAT_803de3e8 = FLOAT_803e2abc;
          }
        }
        FUN_80014b68(0,0x100);
        DAT_803de3dc = 1;
        DAT_803de3de = 0x1e;
        return;
      }
      if (DAT_803de400 == 5) {
        FUN_80022264(0,1);
        FUN_8000d220(dVar4,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
        FLOAT_803de3e8 = FLOAT_803e2abc;
      }
    }
    if (bVar2) {
      if ((((-1 < iVar3) || (param_9 != '\0')) ||
          ((DOUBLE_803e2df0 == (double)FLOAT_803de3e0 && (DOUBLE_803e2df0 < (double)FLOAT_803de3e4))
          )) && (*(int *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 0x18) != 0)) {
        FUN_8012e114(*(int *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 0x18),
                     DAT_803de4a4[DAT_803de458 * 0x20 + 0x1c],1,0);
      }
    }
    else {
      FUN_8012e114(*(undefined4 *)(DAT_803de4a4 + DAT_803de458 * 0x20 + 0x18),
                   DAT_803de4a4[DAT_803de458 * 0x20 + 0x1c],2,0);
    }
  }
  else {
    if ((DAT_803de524 & 0x300) != 0) {
      FUN_8000bb38(0,0x41c);
      FUN_80014b68(0,0x300);
      DAT_803de3de = -0x28;
    }
    DAT_803de3dc = DAT_803de3dc + DAT_803de3de;
    if (0x200 < DAT_803de3dc) {
      DAT_803de3dc = 0x200;
    }
    if (DAT_803de3dc < 0) {
      DAT_803de3dc = 0;
    }
  }
  return;
}

