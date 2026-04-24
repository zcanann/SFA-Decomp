// Function: FUN_802229cc
// Entry: 802229cc
// Size: 1304 bytes

void FUN_802229cc(void)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  double dVar9;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  
  iVar3 = FUN_802860dc();
  piVar8 = *(int **)(iVar3 + 0xb8);
  iVar7 = *(int *)(iVar3 + 0x4c);
  iVar6 = -1;
  iVar5 = piVar8[2];
  if (iVar5 != 0) {
    iVar4 = FUN_80036e58(0x19,iVar3,0);
    bVar1 = false;
    if ((iVar4 != 0) && (iVar5 == iVar4)) {
      bVar1 = true;
    }
    if ((!bVar1) ||
       ((*(char *)((int)piVar8 + 0x12a) < '\0' && (iVar5 = FUN_801a0b14(piVar8[2]), iVar5 == 0)))) {
      piVar8[2] = 0;
      *(byte *)((int)piVar8 + 0x12a) = *(byte *)((int)piVar8 + 0x12a) & 0x7f;
    }
  }
  if ((*(short *)(iVar7 + 0x20) == -1) || (iVar5 = FUN_8001ffb4(), iVar5 != 0)) {
    *(byte *)((int)piVar8 + 0x12a) = *(byte *)((int)piVar8 + 0x12a) & 0xbf | 0x40;
    FUN_8000da58(iVar3,0x3be);
    iVar5 = *piVar8;
    if (iVar5 == 3) {
      if (piVar8[2] != 0) {
        FUN_801a0b90();
        *(byte *)((int)piVar8 + 0x12a) = *(byte *)((int)piVar8 + 0x12a) & 0x7f;
        FUN_80030334((double)FLOAT_803e6ca4,iVar3,0,0);
      }
      piVar8[2] = 0;
      iVar6 = piVar8[1];
    }
    else if (iVar5 < 3) {
      if (iVar5 == 1) {
        if (piVar8[2] == 0) {
          iVar5 = FUN_800801a8(piVar8 + 3);
          if (iVar5 != 0) {
            iVar6 = 5;
          }
        }
        else {
          iVar6 = 3;
        }
      }
      else if (iVar5 < 1) {
        if (-1 < iVar5) {
          if (((piVar8[2] != 0) || (iVar5 = FUN_80036e58(0x19,iVar3,0), iVar5 == 0)) ||
             ((dVar9 = (double)FUN_80021690(iVar3 + 0x18,iVar5 + 0x18),
              (double)FLOAT_803e6cb0 <= dVar9 ||
              (*(float *)(iVar3 + 0x10) <= *(float *)(iVar5 + 0x10))))) {
            iVar5 = FUN_800801a8(piVar8 + 3);
            if (iVar5 != 0) {
              iVar6 = 5;
            }
          }
          else {
            local_3c = *(undefined4 *)(iVar5 + 0xc);
            local_38 = FLOAT_803e6cb4 + *(float *)(iVar5 + 0x10);
            local_34 = *(undefined4 *)(iVar5 + 0x14);
            iVar7 = FUN_80221d6c(iVar3 + 0xc,&local_3c);
            if ((iVar7 != 0) && (iVar7 = FUN_801a0b24(iVar5), iVar7 != 0)) {
              FUN_8000bb18(iVar3,0x3bf);
              iVar6 = 4;
              piVar8[2] = iVar5;
            }
          }
        }
      }
      else {
        if ((int)*(short *)(piVar8 + 0x4a) == (uint)*(byte *)(iVar7 + 0x19)) {
          uStack44 = (int)*(short *)(piVar8 + 0x4a) ^ 0x80000000;
          local_30 = 0x43300000;
          iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e6cc8) *
                       FLOAT_803e6ca8);
          local_28 = (longlong)iVar5;
          *(short *)(piVar8 + 0x4a) = (short)iVar5;
        }
        else {
          *(ushort *)(piVar8 + 0x4a) = (ushort)*(byte *)(iVar7 + 0x19);
        }
        FUN_8008016c(piVar8 + 3);
        iVar6 = 5;
      }
    }
    else if (iVar5 == 5) {
      uStack44 = (int)*(short *)(piVar8 + 0x4a) ^ 0x80000000;
      local_30 = 0x43300000;
      iVar5 = FUN_80222358((double)(FLOAT_803e6cb8 *
                                    (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e6cc8)
                                   * FLOAT_803db414),(double)FLOAT_803e6cbc,(double)FLOAT_803e6cb4,
                           iVar3,piVar8 + 8,1);
      FUN_8002b95c((double)*(float *)(iVar3 + 0x24),(double)*(float *)(iVar3 + 0x28),
                   (double)*(float *)(iVar3 + 0x2c),iVar3);
      if (iVar5 != 0) {
        iVar6 = iVar5 + -1;
        FUN_8008016c(piVar8 + 3);
        FUN_80080178(piVar8 + 3,(int)*(short *)(iVar7 + 0x1a));
        fVar2 = FLOAT_803e6ca4;
        *(float *)(iVar3 + 0x24) = FLOAT_803e6ca4;
        *(float *)(iVar3 + 0x28) = fVar2;
        *(float *)(iVar3 + 0x2c) = fVar2;
      }
    }
    else if (iVar5 < 5) {
      if ((piVar8[2] == 0) || (iVar5 = FUN_801a0b24(), iVar5 == 0)) {
        *piVar8 = 0;
        piVar8[2] = 0;
        *(byte *)((int)piVar8 + 0x12a) = *(byte *)((int)piVar8 + 0x12a) & 0x7f;
      }
      else {
        dVar9 = (double)FUN_80021690(iVar3 + 0x18,piVar8[2] + 0x18);
        if (dVar9 <= (double)FLOAT_803e6cb0) {
          FUN_80247754(piVar8 + 5,piVar8[2] + 0xc,&local_48);
          if (((local_48 != FLOAT_803e6ca4) || (local_44 != FLOAT_803e6ca4)) ||
             (local_40 != FLOAT_803e6ca4)) {
            FUN_80247794(&local_48,&local_48);
          }
          FUN_80247778((double)FLOAT_803dc3b0,&local_48,&local_48);
          FUN_801a0ef8(piVar8[2],&local_48);
          dVar9 = (double)FUN_80247984(piVar8 + 5,piVar8[2] + 0xc);
          if ((dVar9 < (double)FLOAT_803e6ca0) || ((float)piVar8[6] < *(float *)(piVar8[2] + 0x10)))
          {
            FUN_8000bb18(iVar3,0x3c0);
            FUN_801a0bdc(piVar8[2]);
            iVar6 = piVar8[1];
            *(byte *)((int)piVar8 + 0x12a) = *(byte *)((int)piVar8 + 0x12a) & 0x7f | 0x80;
            FUN_80030334((double)FLOAT_803e6ca4,iVar3,0,0);
          }
        }
        else {
          iVar6 = piVar8[1];
          *(byte *)((int)piVar8 + 0x12a) = *(byte *)((int)piVar8 + 0x12a) & 0x7f;
          piVar8[2] = 0;
        }
      }
    }
    FUN_8002fa48((double)FLOAT_803e6cc0,(double)FLOAT_803db414,iVar3,0);
    if ((iVar6 != -1) && (iVar6 != *piVar8)) {
      piVar8[1] = *piVar8;
      *piVar8 = iVar6;
    }
    if (((*(ushort *)(iVar3 + 0xb0) & 0x800) == 0) && (piVar8[2] != 0)) {
      piVar8[5] = *(int *)(iVar3 + 0xc);
      piVar8[6] = (int)(*(float *)(iVar3 + 0x10) + FLOAT_803dc3b4);
      piVar8[7] = *(int *)(iVar3 + 0x14);
      *(int *)(piVar8[2] + 0xc) = piVar8[5];
      *(int *)(piVar8[2] + 0x10) = piVar8[6];
      *(int *)(piVar8[2] + 0x14) = piVar8[7];
    }
  }
  else {
    *(byte *)((int)piVar8 + 0x12a) = *(byte *)((int)piVar8 + 0x12a) & 0xbf;
  }
  FUN_80286128();
  return;
}

