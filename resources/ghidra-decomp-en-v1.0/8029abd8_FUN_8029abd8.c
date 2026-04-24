// Function: FUN_8029abd8
// Entry: 8029abd8
// Size: 964 bytes

/* WARNING: Removing unreachable block (ram,0x8029af74) */

int FUN_8029abd8(undefined8 param_1,int param_2,undefined4 param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  ushort uVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f31;
  short local_48 [2];
  undefined auStack68 [6];
  undefined2 local_3e;
  float local_3c;
  undefined auStack56 [4];
  undefined auStack52 [4];
  undefined auStack48 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar6 = *(int *)(param_2 + 0xb8);
  if (DAT_803de42c == '\0') {
    if ((*(short *)(iVar6 + 0x80e) != -1) || ((*(ushort *)(iVar6 + 0x6e2) & 0x800) != 0)) {
      if ((*(ushort *)(iVar6 + 0x6e2) & 0x800) == 0) {
        iVar2 = 0;
        uVar5 = 0x100;
        local_48[0] = *(short *)(iVar6 + 0x80e);
      }
      else {
        iVar2 = FUN_8011f3a8(local_48);
        uVar5 = 0x800;
      }
      if ((*(short *)(iVar6 + 0x80e) != -1) ||
         ((iVar2 == 1 && ((local_48[0] == 0x2d || (local_48[0] == 0x5ce)))))) {
        FUN_80014b3c(0,0x900);
        *(ushort *)(iVar6 + 0x6e2) = *(ushort *)(iVar6 + 0x6e2) & 0xf6ff;
        DAT_803de4b2 = local_48[0];
        if (local_48[0] != *(short *)(iVar6 + 0x80a)) {
          FUN_802ab38c(param_2,iVar6);
        }
        if (DAT_803de4b2 == 0x5ce) {
          if (0 < *(short *)(*(int *)(*(int *)(param_2 + 0xb8) + 0x35c) + 4)) {
            FUN_802a96d8(param_2);
            DAT_803de42c = '\x01';
            FLOAT_803de430 = FLOAT_803e7ea4;
            DAT_803de4b4 = uVar5;
            *(float *)(iVar6 + 0x854) = FLOAT_803e7f58;
            iVar3 = *(int *)(*(int *)(param_2 + 0xb8) + 0x35c);
            iVar2 = *(short *)(iVar3 + 4) + -1;
            if (iVar2 < 0) {
              iVar2 = 0;
            }
            else if (*(short *)(iVar3 + 6) < iVar2) {
              iVar2 = (int)*(short *)(iVar3 + 6);
            }
            *(short *)(iVar3 + 4) = (short)iVar2;
          }
        }
        else if (DAT_803de4b2 < 0x5ce) {
          if (DAT_803de4b2 == 0x2d) {
            if (*(short *)(*(int *)(*(int *)(param_2 + 0xb8) + 0x35c) + 4) < 2) {
              FUN_8000bb18(0,0x10a);
            }
            else {
              iVar2 = FUN_8029a76c(param_1,param_2,param_3);
joined_r0x8029aee0:
              if (iVar2 != 0) goto LAB_8029af74;
            }
          }
        }
        else if (DAT_803de4b2 == 0x958) {
          if (-1 < *(short *)(*(int *)(*(int *)(param_2 + 0xb8) + 0x35c) + 4)) {
            iVar2 = FUN_8029a5e4(param_1,param_2,param_3);
            goto joined_r0x8029aee0;
          }
          FUN_8000bb18(0,0x10a);
        }
      }
    }
  }
  else {
    FUN_8000da58(param_2,0x382);
    fVar1 = *(float *)(iVar6 + 0x854) - FLOAT_803db414;
    *(float *)(iVar6 + 0x854) = fVar1;
    if (fVar1 <= FLOAT_803e7ea4) {
      iVar3 = *(int *)(*(int *)(param_2 + 0xb8) + 0x35c);
      iVar2 = *(short *)(iVar3 + 4) + -1;
      if (iVar2 < 0) {
        iVar2 = 0;
      }
      else if (*(short *)(iVar3 + 6) < iVar2) {
        iVar2 = (int)*(short *)(iVar3 + 6);
      }
      *(short *)(iVar3 + 4) = (short)iVar2;
      *(float *)(iVar6 + 0x854) = FLOAT_803e7f58;
    }
    FUN_8003842c(DAT_803de44c,5,auStack56,auStack52,auStack48,0);
    local_3c = FLOAT_803e7f9c;
    local_3e = 0;
    (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack68,0x200001,0xffffffff,0);
    local_3e = 1;
    (**(code **)(*DAT_803dca88 + 8))(DAT_803de44c,0x7f5,auStack68,0x200001,0xffffffff,0);
    if ((((*(ushort *)(iVar6 + 0x6e0) & DAT_803de4b4) == 0) ||
        (*(short *)(*(int *)(*(int *)(param_2 + 0xb8) + 0x35c) + 4) == 0)) ||
       (iVar2 = FUN_80080204(), iVar2 != 0)) {
      *(undefined2 *)(iVar6 + 0x80a) = 0xffff;
      DAT_803de42c = '\0';
      iVar2 = 0;
      piVar4 = &DAT_80332ed4;
      do {
        if (*piVar4 != 0) {
          FUN_8002cbc4();
          *piVar4 = 0;
        }
        piVar4 = piVar4 + 1;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 7);
      if (DAT_803de454 != 0) {
        FUN_80013e2c();
        DAT_803de454 = 0;
      }
    }
  }
  *(undefined2 *)(iVar6 + 0x80a) = 0xffff;
  iVar2 = 0;
LAB_8029af74:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return iVar2;
}

