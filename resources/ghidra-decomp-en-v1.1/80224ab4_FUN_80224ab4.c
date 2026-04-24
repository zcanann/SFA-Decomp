// Function: FUN_80224ab4
// Entry: 80224ab4
// Size: 3256 bytes

/* WARNING: Removing unreachable block (ram,0x80225748) */
/* WARNING: Removing unreachable block (ram,0x80224ac4) */

void FUN_80224ab4(uint param_1)

{
  char cVar1;
  float fVar2;
  byte bVar3;
  bool bVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined uVar9;
  int iVar10;
  double dVar11;
  float local_48 [2];
  undefined8 local_40;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  
  iVar10 = *(int *)(param_1 + 0xb8);
  iVar5 = FUN_8002bac4();
  local_48[0] = FLOAT_803e79f0;
  if (*(int *)(iVar10 + 0x268) == 0) {
    uVar6 = FUN_80036f50(9,param_1,local_48);
    *(undefined4 *)(iVar10 + 0x268) = uVar6;
    *(undefined *)(param_1 + 0x36) = 0;
  }
  else {
    puVar7 = (undefined4 *)FUN_800395a4(param_1,0);
    if (puVar7 != (undefined4 *)0x0) {
      *puVar7 = 0;
    }
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) & 0xfeff;
    if (*(byte *)(iVar10 + 0x285) >> 5 != 6) {
      if (*(char *)(param_1 + 0xad) == '\x01') {
        uVar8 = FUN_80020078(0x812);
        if (uVar8 == 0) {
          uVar8 = FUN_80020078(0x808);
          if (uVar8 != 0) {
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
        uVar8 = FUN_80020078(0x813);
        if (uVar8 == 0) {
          uVar8 = FUN_80020078(0x809);
          if (uVar8 != 0) {
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
    bVar3 = *(byte *)(iVar10 + 0x285) >> 5;
    if ((bVar3 != 3) && (bVar3 != 5)) {
      if (*(char *)(param_1 + 0xad) == '\x01') {
        FUN_80097dbc((double)FLOAT_803e79f4,(double)FLOAT_803e79f8,(double)FLOAT_803e79f4,
                     (double)FLOAT_803e79f8,param_1,1,3,1,0x32,0,0);
      }
      else {
        FUN_80097dbc((double)FLOAT_803e79f4,(double)FLOAT_803e79f8,(double)FLOAT_803e79f4,
                     (double)FLOAT_803e79f8,param_1,1,1,1,0x32,0,0);
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
      uVar8 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * 8;
      if (0xff < uVar8) {
        uVar8 = 0xff;
      }
      *(char *)(param_1 + 0x36) = (char)uVar8;
      fVar2 = FLOAT_803e79fc;
      *(float *)(param_1 + 0x24) = FLOAT_803e79fc;
      *(float *)(param_1 + 0x2c) = fVar2;
      uVar8 = FUN_80296b74(iVar5,param_1,(undefined *)(iVar10 + 0x282));
      if ((uVar8 & 0xff) != 0) {
        if (*(char *)(param_1 + 0xad) == '\x01') {
          cVar1 = *(char *)(iVar10 + 0x282);
          if (cVar1 == '\0') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,
                               0xffffffff,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar1 == '\x01') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,1,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar1 == '\x02') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,0,
                               0xffffffff);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar1 == '\x03') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x38))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,0,1);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
        }
        else {
          cVar1 = *(char *)(iVar10 + 0x282);
          if (cVar1 == '\0') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x54))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,
                               0xffffffff,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar1 == '\x01') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x54))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,1,0);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar1 == '\x02') {
            uVar9 = (**(code **)(**(int **)(*(int *)(iVar10 + 0x268) + 0x68) + 0x54))
                              (param_1,(int)*(short *)(iVar10 + 0x27e),
                               (int)*(short *)(iVar10 + 0x280),iVar10 + 0x26c,iVar10 + 0x270,0,
                               0xffffffff);
            *(undefined *)(iVar10 + 0x284) = uVar9;
          }
          else if (cVar1 == '\x03') {
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
      fVar2 = *(float *)(param_1 + 0x24);
      if ((FLOAT_803e79fc != fVar2) || (FLOAT_803e79fc != *(float *)(param_1 + 0x2c))) {
        dVar11 = FUN_80293900((double)(fVar2 * fVar2 +
                                      *(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c)));
        fVar2 = (float)(dVar11 - (double)FLOAT_803e7a00);
        if ((float)(dVar11 - (double)FLOAT_803e7a00) < FLOAT_803e79fc) {
          fVar2 = FLOAT_803e79fc;
        }
        dVar11 = (double)(FLOAT_803e79ec + (FLOAT_803e7a04 * fVar2) / FLOAT_803e7a08);
        if ((double)FLOAT_803e7a0c < dVar11) {
          dVar11 = (double)FLOAT_803e7a0c;
        }
        FUN_8000da78(param_1,200);
        local_40 = (double)(longlong)(int)dVar11;
        FUN_8000b9bc((double)FLOAT_803e7a10,param_1,200,(byte)(int)dVar11);
        *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0xef | 0x10;
      }
      FUN_8002ba34((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),(double)FLOAT_803e79fc,
                   (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
      bVar4 = false;
      cVar1 = *(char *)(iVar10 + 0x282);
      if (cVar1 == '\0') {
        if (*(float *)(param_1 + 0x24) < FLOAT_803e7a14) {
          *(float *)(param_1 + 0x24) = FLOAT_803e7a18 * FLOAT_803dc074 + *(float *)(param_1 + 0x24);
        }
        if (*(float *)(iVar10 + 0x26c) <= *(float *)(param_1 + 0xc)) {
          *(float *)(param_1 + 0xc) = *(float *)(iVar10 + 0x26c);
          bVar4 = true;
        }
      }
      else if (cVar1 == '\x01') {
        if (FLOAT_803e7a1c < *(float *)(param_1 + 0x24)) {
          *(float *)(param_1 + 0x24) =
               -(FLOAT_803e7a18 * FLOAT_803dc074 - *(float *)(param_1 + 0x24));
        }
        if (*(float *)(param_1 + 0xc) <= *(float *)(iVar10 + 0x26c)) {
          *(float *)(param_1 + 0xc) = *(float *)(iVar10 + 0x26c);
          bVar4 = true;
        }
      }
      else if (cVar1 == '\x02') {
        if (*(float *)(param_1 + 0x2c) < FLOAT_803e7a14) {
          *(float *)(param_1 + 0x2c) = FLOAT_803e7a18 * FLOAT_803dc074 + *(float *)(param_1 + 0x2c);
        }
        if (*(float *)(iVar10 + 0x270) <= *(float *)(param_1 + 0x14)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar10 + 0x270);
          bVar4 = true;
        }
      }
      else if (cVar1 == '\x03') {
        if (FLOAT_803e7a1c < *(float *)(param_1 + 0x2c)) {
          *(float *)(param_1 + 0x2c) =
               -(FLOAT_803e7a18 * FLOAT_803dc074 - *(float *)(param_1 + 0x2c));
        }
        if (*(float *)(param_1 + 0x14) <= *(float *)(iVar10 + 0x270)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar10 + 0x270);
          bVar4 = true;
        }
      }
      if (FLOAT_803e7a14 < *(float *)(param_1 + 0x24)) {
        *(float *)(param_1 + 0x24) = FLOAT_803e7a14;
      }
      if (*(float *)(param_1 + 0x24) < FLOAT_803e7a1c) {
        *(float *)(param_1 + 0x24) = FLOAT_803e7a1c;
      }
      if (FLOAT_803e7a14 < *(float *)(param_1 + 0x2c)) {
        *(float *)(param_1 + 0x2c) = FLOAT_803e7a14;
      }
      if (*(float *)(param_1 + 0x2c) < FLOAT_803e7a1c) {
        *(float *)(param_1 + 0x2c) = FLOAT_803e7a1c;
      }
      fVar2 = FLOAT_803e79fc;
      if (bVar4) {
        *(float *)(param_1 + 0x24) = FLOAT_803e79fc;
        *(float *)(param_1 + 0x2c) = fVar2;
        if (*(char *)(iVar10 + 0x284) == '\x02') {
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x80;
          if (*(char *)(param_1 + 0xad) == '\x01') {
            uVar8 = FUN_80020000(0x810);
            if (uVar8 != 4) {
              FUN_8000bb38(0,0xca);
            }
          }
          else {
            uVar8 = FUN_80020000(0x811);
            if (uVar8 != 4) {
              FUN_8000bb38(0,0xca);
            }
          }
        }
        else if (*(char *)(iVar10 + 0x284) == '\x01') {
          *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x20;
          if ((*(byte *)(iVar10 + 0x285) >> 4 & 1) != 0) {
            *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0xef;
            FUN_8000bb38(param_1,0xc9);
          }
        }
        else if (*(char *)(param_1 + 0xad) == '\x01') {
          FUN_800201ac(0x808,1);
        }
        else {
          FUN_800201ac(0x809,1);
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
      FUN_80035ff8(param_1);
      if (*(char *)(param_1 + 0x36) == -1) {
        FUN_8000bb38(param_1,0xcb);
      }
      iVar5 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -8;
      if (iVar5 < 0) {
        iVar5 = 0;
      }
      *(char *)(param_1 + 0x36) = (char)iVar5;
      if (*(char *)(param_1 + 0x36) == '\0') {
        iVar5 = FUN_8002bac4();
        iVar5 = FUN_802248f8(param_1,iVar10,iVar5);
        if (iVar5 != 0) {
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
        FUN_80036018(param_1);
        FUN_8000bb38(0,0xcc);
      }
      uVar8 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * 8;
      if (0xff < uVar8) {
        uVar8 = 0xff;
      }
      *(char *)(param_1 + 0x36) = (char)uVar8;
      if (*(char *)(param_1 + 0x36) == -1) {
        *(byte *)(iVar10 + 0x285) = *(byte *)(iVar10 + 0x285) & 0x1f | 0x20;
      }
      break;
    case 6:
      *(undefined *)(param_1 + 0x36) = 0xff;
    case 4:
      puVar7 = (undefined4 *)FUN_800395a4(param_1,0);
      if (puVar7 != (undefined4 *)0x0) {
        *puVar7 = 0x100;
      }
      *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x100;
    }
    local_40 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 0x27c));
    iVar5 = (int)(FLOAT_803e7a20 * FLOAT_803dc074 + (float)(local_40 - DOUBLE_803e7a30));
    local_38 = (longlong)iVar5;
    *(short *)(iVar10 + 0x27c) = (short)iVar5;
    uStack_2c = (uint)*(ushort *)(iVar10 + 0x27c);
    local_30 = 0x43300000;
    dVar11 = (double)FUN_802945e0();
    *(float *)(iVar10 + 0x278) = (float)((double)FLOAT_803e7a24 * dVar11);
    *(float *)(param_1 + 0x10) = *(float *)(iVar10 + 0x274) + *(float *)(iVar10 + 0x278);
  }
  return;
}

