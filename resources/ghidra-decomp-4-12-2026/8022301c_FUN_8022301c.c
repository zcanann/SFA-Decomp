// Function: FUN_8022301c
// Entry: 8022301c
// Size: 1304 bytes

void FUN_8022301c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  byte bVar6;
  uint uVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  double dVar11;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  
  uVar3 = FUN_80286840();
  piVar10 = *(int **)(uVar3 + 0xb8);
  iVar9 = *(int *)(uVar3 + 0x4c);
  iVar8 = -1;
  iVar7 = piVar10[2];
  if (iVar7 != 0) {
    iVar4 = FUN_80036f50(0x19,uVar3,(float *)0x0);
    bVar1 = false;
    if ((iVar4 != 0) && (iVar7 == iVar4)) {
      bVar1 = true;
    }
    if ((!bVar1) ||
       ((*(char *)((int)piVar10 + 0x12a) < '\0' && (bVar6 = FUN_801a1090(piVar10[2]), bVar6 == 0))))
    {
      piVar10[2] = 0;
      *(byte *)((int)piVar10 + 0x12a) = *(byte *)((int)piVar10 + 0x12a) & 0x7f;
    }
  }
  if (((int)*(short *)(iVar9 + 0x20) == 0xffffffff) ||
     (uVar5 = FUN_80020078((int)*(short *)(iVar9 + 0x20)), uVar5 != 0)) {
    *(byte *)((int)piVar10 + 0x12a) = *(byte *)((int)piVar10 + 0x12a) & 0xbf | 0x40;
    FUN_8000da78(uVar3,0x3be);
    iVar7 = *piVar10;
    if (iVar7 == 3) {
      if (piVar10[2] != 0) {
        FUN_801a110c(piVar10[2]);
        *(byte *)((int)piVar10 + 0x12a) = *(byte *)((int)piVar10 + 0x12a) & 0x7f;
        FUN_8003042c((double)FLOAT_803e793c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar3,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      }
      piVar10[2] = 0;
      iVar8 = piVar10[1];
    }
    else if (iVar7 < 3) {
      if (iVar7 == 1) {
        if (piVar10[2] == 0) {
          iVar7 = FUN_80080434((float *)(piVar10 + 3));
          if (iVar7 != 0) {
            iVar8 = 5;
          }
        }
        else {
          iVar8 = 3;
        }
      }
      else if (iVar7 < 1) {
        if (-1 < iVar7) {
          if (((piVar10[2] != 0) || (iVar7 = FUN_80036f50(0x19,uVar3,(float *)0x0), iVar7 == 0)) ||
             ((dVar11 = (double)FUN_80021754((float *)(uVar3 + 0x18),(float *)(iVar7 + 0x18)),
              (double)FLOAT_803e7948 <= dVar11 ||
              (dVar11 = (double)*(float *)(iVar7 + 0x10), (double)*(float *)(uVar3 + 0x10) <= dVar11
              )))) {
            iVar7 = FUN_80080434((float *)(piVar10 + 3));
            if (iVar7 != 0) {
              iVar8 = 5;
            }
          }
          else {
            local_3c = *(float *)(iVar7 + 0xc);
            local_38 = (float)((double)FLOAT_803e794c + dVar11);
            local_34 = *(undefined4 *)(iVar7 + 0x14);
            iVar9 = FUN_802223bc(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 (float *)(uVar3 + 0xc),&local_3c);
            if ((iVar9 != 0) && (iVar9 = FUN_801a10a0(iVar7), iVar9 != 0)) {
              FUN_8000bb38(uVar3,0x3bf);
              iVar8 = 4;
              piVar10[2] = iVar7;
            }
          }
        }
      }
      else {
        if ((int)*(short *)(piVar10 + 0x4a) == (uint)*(byte *)(iVar9 + 0x19)) {
          uStack_2c = (int)*(short *)(piVar10 + 0x4a) ^ 0x80000000;
          local_30 = 0x43300000;
          iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e7960) *
                       FLOAT_803e7940);
          local_28 = (longlong)iVar7;
          *(short *)(piVar10 + 0x4a) = (short)iVar7;
        }
        else {
          *(ushort *)(piVar10 + 0x4a) = (ushort)*(byte *)(iVar9 + 0x19);
        }
        FUN_800803f8(piVar10 + 3);
        iVar8 = 5;
      }
    }
    else if (iVar7 == 5) {
      uStack_2c = (int)*(short *)(piVar10 + 0x4a) ^ 0x80000000;
      local_30 = 0x43300000;
      iVar7 = FUN_802229a8((double)(FLOAT_803e7950 *
                                    (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e7960
                                           ) * FLOAT_803dc074),(double)FLOAT_803e7954,
                           (double)FLOAT_803e794c,uVar3,(float *)(piVar10 + 8),'\x01');
      FUN_8002ba34((double)*(float *)(uVar3 + 0x24),(double)*(float *)(uVar3 + 0x28),
                   (double)*(float *)(uVar3 + 0x2c),uVar3);
      if (iVar7 != 0) {
        iVar8 = iVar7 + -1;
        FUN_800803f8(piVar10 + 3);
        FUN_80080404((float *)(piVar10 + 3),*(short *)(iVar9 + 0x1a));
        fVar2 = FLOAT_803e793c;
        *(float *)(uVar3 + 0x24) = FLOAT_803e793c;
        *(float *)(uVar3 + 0x28) = fVar2;
        *(float *)(uVar3 + 0x2c) = fVar2;
      }
    }
    else if (iVar7 < 5) {
      if ((piVar10[2] == 0) || (iVar7 = FUN_801a10a0(piVar10[2]), iVar7 == 0)) {
        *piVar10 = 0;
        piVar10[2] = 0;
        *(byte *)((int)piVar10 + 0x12a) = *(byte *)((int)piVar10 + 0x12a) & 0x7f;
      }
      else {
        dVar11 = (double)FUN_80021754((float *)(uVar3 + 0x18),(float *)(piVar10[2] + 0x18));
        if (dVar11 <= (double)FLOAT_803e7948) {
          FUN_80247eb8((float *)(piVar10 + 5),(float *)(piVar10[2] + 0xc),&local_48);
          if (((local_48 != FLOAT_803e793c) || (local_44 != FLOAT_803e793c)) ||
             (local_40 != FLOAT_803e793c)) {
            FUN_80247ef8(&local_48,&local_48);
          }
          FUN_80247edc((double)FLOAT_803dd018,&local_48,&local_48);
          FUN_801a1474(piVar10[2],&local_48);
          dVar11 = FUN_802480e8((float *)(piVar10 + 5),(float *)(piVar10[2] + 0xc));
          if ((dVar11 < (double)FLOAT_803e7938) ||
             ((float)piVar10[6] < *(float *)(piVar10[2] + 0x10))) {
            FUN_8000bb38(uVar3,0x3c0);
            FUN_801a1158(piVar10[2]);
            iVar8 = piVar10[1];
            *(byte *)((int)piVar10 + 0x12a) = *(byte *)((int)piVar10 + 0x12a) & 0x7f | 0x80;
            FUN_8003042c((double)FLOAT_803e793c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,uVar3,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
          }
        }
        else {
          iVar8 = piVar10[1];
          *(byte *)((int)piVar10 + 0x12a) = *(byte *)((int)piVar10 + 0x12a) & 0x7f;
          piVar10[2] = 0;
        }
      }
    }
    FUN_8002fb40((double)FLOAT_803e7958,(double)FLOAT_803dc074);
    if ((iVar8 != -1) && (iVar8 != *piVar10)) {
      piVar10[1] = *piVar10;
      *piVar10 = iVar8;
    }
    if (((*(ushort *)(uVar3 + 0xb0) & 0x800) == 0) && (piVar10[2] != 0)) {
      piVar10[5] = *(int *)(uVar3 + 0xc);
      piVar10[6] = (int)(*(float *)(uVar3 + 0x10) + FLOAT_803dd01c);
      piVar10[7] = *(int *)(uVar3 + 0x14);
      *(int *)(piVar10[2] + 0xc) = piVar10[5];
      *(int *)(piVar10[2] + 0x10) = piVar10[6];
      *(int *)(piVar10[2] + 0x14) = piVar10[7];
    }
  }
  else {
    *(byte *)((int)piVar10 + 0x12a) = *(byte *)((int)piVar10 + 0x12a) & 0xbf;
  }
  FUN_8028688c();
  return;
}

