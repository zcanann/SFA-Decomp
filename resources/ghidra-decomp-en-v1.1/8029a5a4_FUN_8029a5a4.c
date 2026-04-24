// Function: FUN_8029a5a4
// Entry: 8029a5a4
// Size: 1500 bytes

/* WARNING: Removing unreachable block (ram,0x8029ab60) */
/* WARNING: Removing unreachable block (ram,0x8029a5b4) */

void FUN_8029a5a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined *param_11,float *param_12,
                 undefined4 *param_13,undefined4 param_14,int param_15,int param_16)

{
  char cVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  undefined8 extraout_f1_00;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar10;
  undefined auStack_48 [6];
  undefined2 local_42;
  float local_40;
  float fStack_3c;
  undefined4 uStack_38;
  float afStack_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar10 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar8 = *(int *)(psVar3 + 0x5c);
  uVar10 = extraout_f1;
  if (DAT_803df0ac != '\0') {
    FUN_8000da78((uint)psVar3,0x382);
    fVar2 = *(float *)(iVar8 + 0x854) - FLOAT_803dc074;
    *(float *)(iVar8 + 0x854) = fVar2;
    if (fVar2 <= FLOAT_803e8b3c) {
      iVar6 = *(int *)(*(int *)(psVar3 + 0x5c) + 0x35c);
      iVar4 = *(short *)(iVar6 + 4) + -1;
      if (iVar4 < 0) {
        iVar4 = 0;
      }
      else if (*(short *)(iVar6 + 6) < iVar4) {
        iVar4 = (int)*(short *)(iVar6 + 6);
      }
      *(short *)(iVar6 + 4) = (short)iVar4;
      *(float *)(iVar8 + 0x854) = FLOAT_803e8bf0;
    }
    FUN_80038524(DAT_803df0cc,5,&fStack_3c,&uStack_38,afStack_34,0);
    local_40 = FLOAT_803e8c34;
    local_42 = 0;
    (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x7f5,auStack_48,0x200001,0xffffffff,0);
    local_42 = 1;
    param_11 = auStack_48;
    param_12 = (float *)0x200001;
    param_13 = (undefined4 *)0xffffffff;
    param_14 = 0;
    param_15 = *DAT_803dd708;
    uVar9 = (**(code **)(param_15 + 8))(DAT_803df0cc,0x7f5);
    if ((((*(ushort *)(iVar8 + 0x6e0) & DAT_803df134) == 0) ||
        (*(short *)(*(int *)(*(int *)(psVar3 + 0x5c) + 0x35c) + 4) == 0)) ||
       (iVar4 = FUN_80080490(), uVar9 = extraout_f1_00, iVar4 != 0)) {
      DAT_803df0ac = '\0';
      iVar4 = 0;
      piVar7 = &DAT_80333b34;
      do {
        if (*piVar7 != 0) {
          uVar9 = FUN_8002cc9c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar7
                              );
          *piVar7 = 0;
        }
        piVar7 = piVar7 + 1;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 7);
      if (DAT_803df0d4 != (undefined *)0x0) {
        FUN_80013e4c(DAT_803df0d4);
        DAT_803df0d4 = (undefined *)0x0;
      }
    }
  }
  if ((*(short *)(iVar8 + 0x80e) != -1) || ((*(uint *)(iVar5 + 0x31c) & 0x800) != 0)) {
    iVar4 = FUN_8029b338(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar3,iVar5
                         ,param_11,param_12,param_13,param_14,param_15,param_16);
    if (iVar4 != 0) goto LAB_8029ab60;
    *(undefined2 *)(iVar8 + 0x80e) = 0xffff;
  }
  if ((*(uint *)(iVar5 + 0x31c) & 0x400) == 0) {
    if ((*(uint *)(iVar5 + 0x31c) & 0x100) != 0) {
      cVar1 = *(char *)(iVar5 + 0x34b);
      if ((cVar1 != '\x02') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e8b44)) {
        if ((cVar1 != '\x03') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e8b44)) {
          if ((cVar1 != '\x01') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e8b44)) {
            if ((cVar1 != '\x04') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e8b44)) {
              *(undefined *)(iVar8 + 0x8a9) = 0;
              FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,psVar3,
                           (int)*(short *)(&DAT_8033431c +
                                          *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                     (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2)
                           ,0,param_12,param_13,param_14,param_15,param_16);
              *(code **)(iVar5 + 0x308) = FUN_8029c368;
            }
            else {
              *(undefined *)(iVar8 + 0x8a9) = 2;
              FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,psVar3,
                           (int)*(short *)(&DAT_8033431c +
                                          *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                     (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2)
                           ,0,param_12,param_13,param_14,param_15,param_16);
              *(code **)(iVar5 + 0x308) = FUN_8029c368;
            }
          }
          else {
            *(undefined *)(iVar8 + 0x8a9) = 3;
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,psVar3,
                         (int)*(short *)(&DAT_8033431c +
                                        *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                   (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0
                         ,param_12,param_13,param_14,param_15,param_16);
            *(code **)(iVar5 + 0x308) = FUN_8029c368;
          }
        }
        else {
          *(undefined *)(iVar8 + 0x8a9) = 4;
          FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,psVar3,
                       (int)*(short *)(&DAT_8033431c +
                                      *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                 (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),0,
                       param_12,param_13,param_14,param_15,param_16);
          *(code **)(iVar5 + 0x308) = FUN_8029c368;
        }
      }
      else {
        *(undefined *)(iVar8 + 0x8a9) = 1;
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     psVar3,(int)*(short *)(&DAT_8033431c +
                                           *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                      (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2
                                           ),0,param_12,param_13,param_14,param_15,param_16);
        *(code **)(iVar5 + 0x308) = FUN_8029c368;
      }
    }
  }
  else {
    cVar1 = *(char *)(iVar5 + 0x34b);
    if (cVar1 == '\x01') {
      *(undefined *)(iVar8 + 0x8a9) = 8;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar3,(int)*(short *)(&DAT_8033431c +
                                         *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                    (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),
                   0,param_12,param_13,param_14,param_15,param_16);
      *(code **)(iVar5 + 0x308) = FUN_8029c368;
    }
    else if (cVar1 == '\x03') {
      *(undefined *)(iVar8 + 0x8a9) = 9;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar3,(int)*(short *)(&DAT_8033431c +
                                         *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                    (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),
                   0,param_12,param_13,param_14,param_15,param_16);
      *(code **)(iVar5 + 0x308) = FUN_8029c368;
    }
    else if (cVar1 == '\x04') {
      *(undefined *)(iVar8 + 0x8a9) = 7;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar3,(int)*(short *)(&DAT_8033431c +
                                         *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                    (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),
                   0,param_12,param_13,param_14,param_15,param_16);
      *(code **)(iVar5 + 0x308) = FUN_8029c368;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar8 + 0x8a9) = 6;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar3,(int)*(short *)(&DAT_8033431c +
                                         *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                    (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),
                   0,param_12,param_13,param_14,param_15,param_16);
      *(code **)(iVar5 + 0x308) = FUN_8029c368;
    }
    else {
      *(undefined *)(iVar8 + 0x8a9) = 5;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar3,(int)*(short *)(&DAT_8033431c +
                                         *(short *)(*(int *)(iVar8 + 0x3dc) +
                                                    (uint)*(byte *)(iVar8 + 0x8a9) * 0xb0 + 2) * 2),
                   0,param_12,param_13,param_14,param_15,param_16);
      *(code **)(iVar5 + 0x308) = FUN_8029c368;
    }
  }
LAB_8029ab60:
  FUN_80286888();
  return;
}

