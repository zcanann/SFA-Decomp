// Function: FUN_80224464
// Entry: 80224464
// Size: 3256 bytes

/* WARNING: Removing unreachable block (ram,0x802250f8) */

void FUN_80224464(int param_1)

{
  float fVar1;
  byte bVar2;
  bool bVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  char cVar8;
  undefined uVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  float local_48 [2];
  double local_40;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar10 = *(int *)(param_1 + 0xb8);
  uVar5 = FUN_8002b9ec();
  local_48[0] = FLOAT_803e6d58;
  if (*(int *)(iVar10 + 0x268) == 0) {
    uVar5 = FUN_80036e58(9,param_1,local_48);
    *(undefined4 *)(iVar10 + 0x268) = uVar5;
    *(undefined *)(param_1 + 0x36) = 0;
  }
  else {
    puVar6 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar6 != (undefined4 *)0x0) {
      *puVar6 = 0;
    }
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) & 0xfeff;
    if (*(byte *)(iVar10 + 0x285) >> 5 != 6) {
      if (*(char *)(param_1 + 0xad) == '\x01') {
        iVar7 = FUN_8001ffb4(0x812);
        if (iVar7 == 0) {
          iVar7 = FUN_8001ffb4(0x808);
          if (iVar7 != 0) {
            *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x60;
          }
        }
        else {
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0xc0;
          (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x34))
                    (*(undefined *)(iVar10 + 0x283),iVar10 + 0x27e,iVar10 + 0x280);
          (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x20))
                    (param_1,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280),
                     param_1 + 0xc,param_1 + 0x14);
        }
      }
      else {
        iVar7 = FUN_8001ffb4(0x813);
        if (iVar7 == 0) {
          iVar7 = FUN_8001ffb4(0x809);
          if (iVar7 != 0) {
            *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x60;
          }
        }
        else {
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0xc0;
          (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x50))
                    (*(undefined *)(iVar10 + 0x283),iVar10 + 0x27e,iVar10 + 0x280);
          (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x3c))
                    (param_1,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280),
                     param_1 + 0xc,param_1 + 0x14);
        }
      }
    }
    bVar2 = *(byte *)(iVar10 + 0x285) >> 5;
    if ((bVar2 != 3) && (bVar2 != 5)) {
      if (*(char *)(param_1 + 0xad) == '\x01') {
        FUN_80097b30((double)FLOAT_803e6d5c,(double)FLOAT_803e6d60,(double)FLOAT_803e6d5c,
                     (double)FLOAT_803e6d60,param_1,1,3,1,0x32,0,0);
      }
      else {
        FUN_80097b30((double)FLOAT_803e6d5c,(double)FLOAT_803e6d60,(double)FLOAT_803e6d5c,
                     (double)FLOAT_803e6d60,param_1,1,1,1,0x32,0,0);
      }
    }
    switch(*(byte *)(iVar10 + 0x285) >> 5) {
    case 0:
      if (*(char *)(param_1 + 0xad) == '\x01') {
        (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x30))
                  (*(undefined *)(iVar10 + 0x283),iVar10 + 0x27e,iVar10 + 0x280);
        (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x20))
                  (param_1,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280),
                   param_1 + 0xc,param_1 + 0x14);
      }
      else {
        (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x4c))
                  (*(undefined *)(iVar10 + 0x283),iVar10 + 0x27e,iVar10 + 0x280);
        (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x3c))
                  (param_1,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280),
                   param_1 + 0xc,param_1 + 0x14);
      }
      *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x20;
      break;
    case 1:
      uVar4 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * 8;
      if (0xff < uVar4) {
        uVar4 = 0xff;
      }
      *(char *)(param_1 + 0x36) = (char)uVar4;
      fVar1 = FLOAT_803e6d64;
      *(float *)(param_1 + 0x24) = FLOAT_803e6d64;
      *(float *)(param_1 + 0x2c) = fVar1;
      cVar8 = FUN_80296414(uVar5,param_1,iVar10 + 0x282);
      if (cVar8 != '\0') {
        if (*(char *)(param_1 + 0xad) == '\x01') {
          cVar8 = *(char *)(iVar10 + 0x282);
          if (cVar8 == '\0') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,
                               0xffffffff,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar8 == '\x01') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,1,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar8 == '\x02') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,0,
                               0xffffffff);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar8 == '\x03') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,0,1);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
        }
        else {
          cVar8 = *(char *)(iVar10 + 0x282);
          if (cVar8 == '\0') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x54))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,
                               0xffffffff,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar8 == '\x01') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x54))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,1,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar8 == '\x02') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x54))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,0,
                               0xffffffff);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar8 == '\x03') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x54))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,0,1);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
        }
        if ((*(float *)(iVar10 + 0x26c) != *(float *)(param_1 + 0xc)) ||
           (*(float *)(iVar10 + 0x270) != *(float *)(param_1 + 0x10))) {
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x40;
        }
      }
      break;
    case 2:
      fVar1 = *(float *)(param_1 + 0x24);
      if ((FLOAT_803e6d64 != fVar1) || (FLOAT_803e6d64 != *(float *)(param_1 + 0x2c))) {
        dVar12 = (double)FUN_802931a0((double)(fVar1 * fVar1 +
                                              *(float *)(param_1 + 0x2c) *
                                              *(float *)(param_1 + 0x2c)));
        fVar1 = (float)(dVar12 - (double)FLOAT_803e6d68);
        if ((float)(dVar12 - (double)FLOAT_803e6d68) < FLOAT_803e6d64) {
          fVar1 = FLOAT_803e6d64;
        }
        dVar12 = (double)(FLOAT_803e6d54 + (FLOAT_803e6d6c * fVar1) / FLOAT_803e6d70);
        if ((double)FLOAT_803e6d74 < dVar12) {
          dVar12 = (double)FLOAT_803e6d74;
        }
        FUN_8000da58(param_1,200);
        local_40 = (double)(longlong)(int)dVar12;
        FUN_8000b99c((double)FLOAT_803e6d78,param_1,200,(int)dVar12);
        *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0xef | 0x10;
      }
      FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),(double)FLOAT_803e6d64,
                   (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
      bVar3 = false;
      cVar8 = *(char *)(iVar10 + 0x282);
      if (cVar8 == '\0') {
        if (*(float *)(param_1 + 0x24) < FLOAT_803e6d7c) {
          *(float *)(param_1 + 0x24) = FLOAT_803e6d80 * FLOAT_803db414 + *(float *)(param_1 + 0x24);
        }
        if (*(float *)(iVar10 + 0x26c) <= *(float *)(param_1 + 0xc)) {
          *(float *)(param_1 + 0xc) = *(float *)(iVar10 + 0x26c);
          bVar3 = true;
        }
      }
      else if (cVar8 == '\x01') {
        if (FLOAT_803e6d84 < *(float *)(param_1 + 0x24)) {
          *(float *)(param_1 + 0x24) =
               -(FLOAT_803e6d80 * FLOAT_803db414 - *(float *)(param_1 + 0x24));
        }
        if (*(float *)(param_1 + 0xc) <= *(float *)(iVar10 + 0x26c)) {
          *(float *)(param_1 + 0xc) = *(float *)(iVar10 + 0x26c);
          bVar3 = true;
        }
      }
      else if (cVar8 == '\x02') {
        if (*(float *)(param_1 + 0x2c) < FLOAT_803e6d7c) {
          *(float *)(param_1 + 0x2c) = FLOAT_803e6d80 * FLOAT_803db414 + *(float *)(param_1 + 0x2c);
        }
        if (*(float *)(iVar10 + 0x270) <= *(float *)(param_1 + 0x14)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar10 + 0x270);
          bVar3 = true;
        }
      }
      else if (cVar8 == '\x03') {
        if (FLOAT_803e6d84 < *(float *)(param_1 + 0x2c)) {
          *(float *)(param_1 + 0x2c) =
               -(FLOAT_803e6d80 * FLOAT_803db414 - *(float *)(param_1 + 0x2c));
        }
        if (*(float *)(param_1 + 0x14) <= *(float *)(iVar10 + 0x270)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar10 + 0x270);
          bVar3 = true;
        }
      }
      if (FLOAT_803e6d7c < *(float *)(param_1 + 0x24)) {
        *(float *)(param_1 + 0x24) = FLOAT_803e6d7c;
      }
      if (*(float *)(param_1 + 0x24) < FLOAT_803e6d84) {
        *(float *)(param_1 + 0x24) = FLOAT_803e6d84;
      }
      if (FLOAT_803e6d7c < *(float *)(param_1 + 0x2c)) {
        *(float *)(param_1 + 0x2c) = FLOAT_803e6d7c;
      }
      if (*(float *)(param_1 + 0x2c) < FLOAT_803e6d84) {
        *(float *)(param_1 + 0x2c) = FLOAT_803e6d84;
      }
      fVar1 = FLOAT_803e6d64;
      if (bVar3) {
        *(float *)(param_1 + 0x24) = FLOAT_803e6d64;
        *(float *)(param_1 + 0x2c) = fVar1;
        if (*(char *)(iVar10 + 0x284) == '\x02') {
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x80;
          if (*(char *)(param_1 + 0xad) == '\x01') {
            iVar7 = FUN_8001ff3c(0x810);
            if (iVar7 != 4) {
              FUN_8000bb18(0,0xca);
            }
          }
          else {
            iVar7 = FUN_8001ff3c(0x811);
            if (iVar7 != 4) {
              FUN_8000bb18(0,0xca);
            }
          }
        }
        else if (*(char *)(iVar10 + 0x284) == '\x01') {
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x20;
          if ((*(byte *)(iVar10 + 0x285) >> 4 & 1) != 0) {
            *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0xef;
            FUN_8000bb18(param_1,0xc9);
          }
        }
        else if (*(char *)(param_1 + 0xad) == '\x01') {
          FUN_800200e8(0x808,1);
        }
        else {
          FUN_800200e8(0x809,1);
        }
        if (*(byte *)(iVar10 + 0x285) >> 5 != 3) {
          if (*(char *)(param_1 + 0xad) == '\x01') {
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x28))
                      (0,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280));
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x24))
                      ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x14),param_1,
                       iVar10 + 0x27e,iVar10 + 0x280);
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x28))
                      (*(undefined *)(iVar10 + 0x283),(int)*(short *)(iVar10 + 0x27e),
                       (int)*(short *)(iVar10 + 0x280));
          }
          else {
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x44))
                      (0,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280));
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x40))
                      ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x14),param_1,
                       iVar10 + 0x27e,iVar10 + 0x280);
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x44))
                      (*(undefined *)(iVar10 + 0x283),(int)*(short *)(iVar10 + 0x27e),
                       (int)*(short *)(iVar10 + 0x280));
          }
        }
      }
      break;
    case 3:
      FUN_80035f00(param_1);
      if (*(char *)(param_1 + 0x36) == -1) {
        FUN_8000bb18(param_1,0xcb);
      }
      iVar7 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * -8;
      if (iVar7 < 0) {
        iVar7 = 0;
      }
      *(char *)(param_1 + 0x36) = (char)iVar7;
      if (*(char *)(param_1 + 0x36) == '\0') {
        uVar5 = FUN_8002b9ec();
        iVar7 = FUN_802242a8(param_1,iVar10,uVar5);
        if (iVar7 != 0) {
          if (*(char *)(param_1 + 0xad) == '\x01') {
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x30))
                      (*(undefined *)(iVar10 + 0x283),iVar10 + 0x27e,iVar10 + 0x280);
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x20))
                      (param_1,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280),
                       param_1 + 0xc,param_1 + 0x14);
          }
          else {
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x4c))
                      (*(undefined *)(iVar10 + 0x283),iVar10 + 0x27e,iVar10 + 0x280);
            (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x3c))
                      (param_1,(int)*(short *)(iVar10 + 0x27e),(int)*(short *)(iVar10 + 0x280),
                       param_1 + 0xc,param_1 + 0x14);
          }
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0xa0;
        }
      }
      break;
    case 5:
      if (*(char *)(param_1 + 0x36) == '\0') {
        FUN_80035f20(param_1);
        FUN_8000bb18(0,0xcc);
      }
      uVar4 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * 8;
      if (0xff < uVar4) {
        uVar4 = 0xff;
      }
      *(char *)(param_1 + 0x36) = (char)uVar4;
      if (*(char *)(param_1 + 0x36) == -1) {
        *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x20;
      }
      break;
    case 6:
      *(undefined *)(param_1 + 0x36) = 0xff;
    case 4:
      puVar6 = (undefined4 *)FUN_800394ac(param_1,0,0);
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0x100;
      }
      *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x100;
    }
    dVar12 = DOUBLE_803e6d98;
    local_40 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 0x27c));
    iVar7 = (int)(FLOAT_803e6d88 * FLOAT_803db414 + (float)(local_40 - DOUBLE_803e6d98));
    local_38 = (longlong)iVar7;
    *(short *)(iVar10 + 0x27c) = (short)iVar7;
    uStack44 = (uint)*(ushort *)(iVar10 + 0x27c);
    local_30 = 0x43300000;
    dVar12 = (double)FUN_80293e80((double)((FLOAT_803e6d90 *
                                           (float)((double)CONCAT44(0x43300000,uStack44) - dVar12))
                                          / FLOAT_803e6d94));
    *(float *)(iVar10 + 0x278) = (float)((double)FLOAT_803e6d8c * dVar12);
    *(float *)(param_1 + 0x10) = *(float *)(iVar10 + 0x274) + *(float *)(iVar10 + 0x278);
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return;
}

