// Function: FUN_8029b338
// Entry: 8029b338
// Size: 964 bytes

/* WARNING: Removing unreachable block (ram,0x8029b6d4) */
/* WARNING: Removing unreachable block (ram,0x8029b348) */

int FUN_8029b338(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)

{
  float fVar1;
  int iVar2;
  short sVar3;
  int iVar4;
  int *piVar5;
  ushort uVar6;
  int iVar7;
  undefined8 uVar8;
  undefined8 extraout_f1;
  short local_48 [2];
  undefined auStack_44 [6];
  undefined2 local_3e;
  float local_3c;
  float fStack_38;
  undefined4 uStack_34;
  float afStack_30 [4];
  
  iVar7 = *(int *)(param_9 + 0x5c);
  if (DAT_803df0ac == '\0') {
    if ((*(short *)(iVar7 + 0x80e) != -1) || ((*(ushort *)(iVar7 + 0x6e2) & 0x800) != 0)) {
      if ((*(ushort *)(iVar7 + 0x6e2) & 0x800) == 0) {
        sVar3 = 0;
        uVar6 = 0x100;
        local_48[0] = *(short *)(iVar7 + 0x80e);
      }
      else {
        sVar3 = FUN_8011f68c(local_48);
        uVar6 = 0x800;
      }
      if ((*(short *)(iVar7 + 0x80e) != -1) ||
         ((sVar3 == 1 && ((local_48[0] == 0x2d || (local_48[0] == 0x5ce)))))) {
        uVar8 = FUN_80014b68(0,0x900);
        *(ushort *)(iVar7 + 0x6e2) = *(ushort *)(iVar7 + 0x6e2) & 0xf6ff;
        iVar2 = (int)local_48[0];
        DAT_803df132 = local_48[0];
        if (iVar2 != *(short *)(iVar7 + 0x80a)) {
          uVar8 = FUN_802abaec((uint)param_9,iVar7,iVar2);
        }
        if (DAT_803df132 == 0x5ce) {
          if (0 < *(short *)(*(int *)(*(int *)(param_9 + 0x5c) + 0x35c) + 4)) {
            FUN_802a9e38(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            DAT_803df0ac = '\x01';
            FLOAT_803df0b0 = FLOAT_803e8b3c;
            DAT_803df134 = uVar6;
            *(float *)(iVar7 + 0x854) = FLOAT_803e8bf0;
            iVar4 = *(int *)(*(int *)(param_9 + 0x5c) + 0x35c);
            iVar2 = *(short *)(iVar4 + 4) + -1;
            if (iVar2 < 0) {
              iVar2 = 0;
            }
            else if (*(short *)(iVar4 + 6) < iVar2) {
              iVar2 = (int)*(short *)(iVar4 + 6);
            }
            *(short *)(iVar4 + 4) = (short)iVar2;
          }
        }
        else {
          if (DAT_803df132 < 0x5ce) {
            if (DAT_803df132 != 0x2d) goto LAB_8029b6c8;
            if (*(short *)(*(int *)(*(int *)(param_9 + 0x5c) + 0x35c) + 4) < 2) {
              FUN_8000bb38(0,0x10a);
              goto LAB_8029b6c8;
            }
            iVar2 = FUN_8029aecc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          }
          else {
            if (DAT_803df132 != 0x958) goto LAB_8029b6c8;
            if (*(short *)(*(int *)(*(int *)(param_9 + 0x5c) + 0x35c) + 4) < 0) {
              FUN_8000bb38(0,0x10a);
              goto LAB_8029b6c8;
            }
            iVar2 = FUN_8029ad44(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,param_10,iVar2,param_12,param_13,param_14,param_15,param_16
                                );
          }
          if (iVar2 != 0) {
            return iVar2;
          }
        }
      }
    }
  }
  else {
    FUN_8000da78((uint)param_9,0x382);
    fVar1 = *(float *)(iVar7 + 0x854) - FLOAT_803dc074;
    *(float *)(iVar7 + 0x854) = fVar1;
    if (fVar1 <= FLOAT_803e8b3c) {
      iVar4 = *(int *)(*(int *)(param_9 + 0x5c) + 0x35c);
      iVar2 = *(short *)(iVar4 + 4) + -1;
      if (iVar2 < 0) {
        iVar2 = 0;
      }
      else if (*(short *)(iVar4 + 6) < iVar2) {
        iVar2 = (int)*(short *)(iVar4 + 6);
      }
      *(short *)(iVar4 + 4) = (short)iVar2;
      *(float *)(iVar7 + 0x854) = FLOAT_803e8bf0;
    }
    FUN_80038524(DAT_803df0cc,5,&fStack_38,&uStack_34,afStack_30,0);
    local_3c = FLOAT_803e8c34;
    local_3e = 0;
    (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x7f5,auStack_44,0x200001,0xffffffff,0);
    local_3e = 1;
    uVar8 = (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x7f5,auStack_44,0x200001,0xffffffff,0);
    if ((((*(ushort *)(iVar7 + 0x6e0) & DAT_803df134) == 0) ||
        (*(short *)(*(int *)(*(int *)(param_9 + 0x5c) + 0x35c) + 4) == 0)) ||
       (iVar2 = FUN_80080490(), uVar8 = extraout_f1, iVar2 != 0)) {
      *(undefined2 *)(iVar7 + 0x80a) = 0xffff;
      DAT_803df0ac = '\0';
      iVar2 = 0;
      piVar5 = &DAT_80333b34;
      do {
        if (*piVar5 != 0) {
          uVar8 = FUN_8002cc9c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar5
                              );
          *piVar5 = 0;
        }
        piVar5 = piVar5 + 1;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 7);
      if (DAT_803df0d4 != (undefined *)0x0) {
        FUN_80013e4c(DAT_803df0d4);
        DAT_803df0d4 = (undefined *)0x0;
      }
    }
  }
LAB_8029b6c8:
  *(undefined2 *)(iVar7 + 0x80a) = 0xffff;
  return 0;
}

