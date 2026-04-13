// Function: FUN_8022e0a0
// Entry: 8022e0a0
// Size: 2180 bytes

void FUN_8022e0a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  float fVar2;
  char cVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined4 uVar6;
  int iVar7;
  double dVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  undefined4 local_158;
  undefined4 local_154;
  ushort local_150;
  ushort local_14e;
  undefined2 local_14c;
  undefined8 local_148;
  undefined8 local_140;
  longlong local_138;
  longlong local_130;
  undefined4 local_128;
  uint uStack_124;
  longlong local_120;
  undefined4 local_118;
  uint uStack_114;
  longlong local_110;
  undefined4 local_108;
  uint uStack_104;
  longlong local_100;
  undefined4 local_f8;
  uint uStack_f4;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack_e4;
  longlong local_e0;
  undefined4 local_d8;
  uint uStack_d4;
  longlong local_d0;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  longlong local_b8;
  undefined4 local_b0;
  uint uStack_ac;
  undefined4 local_a8;
  uint uStack_a4;
  longlong local_a0;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  longlong local_88;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  iVar7 = *(int *)(param_9 + 0x5c);
  if ((*(byte *)(iVar7 + 0x477) & 1) == 0) {
    FUN_8022d4b0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,iVar7)
    ;
  }
  else {
    cVar3 = *(char *)(iVar7 + 0x478);
    if (cVar3 == '\x05') {
      fVar2 = *(float *)(iVar7 + 0x46c) - FLOAT_803dc074;
      *(float *)(iVar7 + 0x46c) = fVar2;
      if (fVar2 <= FLOAT_803e7b64) {
        *(undefined *)(iVar7 + 0x478) = 6;
        (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
        *(float *)(iVar7 + 0x46c) = FLOAT_803e7bcc;
      }
    }
    else if (cVar3 == '\x06') {
      fVar2 = *(float *)(iVar7 + 0x46c) - FLOAT_803dc074;
      dVar8 = (double)fVar2;
      *(float *)(iVar7 + 0x46c) = fVar2;
      if (dVar8 <= (double)FLOAT_803e7b64) {
        if (*(char *)(param_9 + 0x56) == '&') {
          uVar6 = 1;
          FUN_80043604(0,0,1);
          uVar4 = FUN_8004832c(0x26);
          FUN_80043658(uVar4,0);
          uVar4 = FUN_8004832c(0xb);
          FUN_80043658(uVar4,1);
          FUN_80055464(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,'\0',uVar6
                       ,param_12,param_13,param_14,param_15,param_16);
        }
        else {
          FUN_80055464(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x60,'\0',
                       param_11,param_12,param_13,param_14,param_15,param_16);
        }
      }
    }
    else {
      if (cVar3 == '\x04') {
        fVar2 = *(float *)(iVar7 + 0x46c) - FLOAT_803dc074;
        *(float *)(iVar7 + 0x46c) = fVar2;
        if (fVar2 <= FLOAT_803e7b64) {
          *(undefined *)(iVar7 + 0x478) = 5;
          *(float *)(iVar7 + 0x46c) = FLOAT_803e7bbc;
          param_9[3] = param_9[3] | 0x4000;
          FUN_8009adfc((double)FLOAT_803e7bc0,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,1,0,1,1,0,1,0);
        }
        local_148 = (double)CONCAT44(0x43300000,*(uint *)(iVar7 + 0x36c) ^ 0x80000000);
        iVar1 = (int)(FLOAT_803e7c04 * FLOAT_803dc074 + (float)(local_148 - DOUBLE_803e7b78));
        local_140 = (double)(longlong)iVar1;
        *(int *)(iVar7 + 0x36c) = iVar1;
        param_9[2] = (ushort)*(undefined4 *)(iVar7 + 0x36c);
        *(float *)(iVar7 + 0x4c) = -(FLOAT_803e7b90 * FLOAT_803dc074 - *(float *)(iVar7 + 0x4c));
        dVar10 = (double)(*(float *)(iVar7 + 0x4c) * FLOAT_803dc074);
        dVar11 = (double)(*(float *)(iVar7 + 0x50) * FLOAT_803dc074);
        FUN_8002ba34((double)(*(float *)(iVar7 + 0x48) * FLOAT_803dc074),dVar10,dVar11,(int)param_9)
        ;
        FUN_8022b4e0((int)param_9,iVar7);
        *(ushort *)(*(int *)(iVar7 + 0x418) + 6) = *(ushort *)(*(int *)(iVar7 + 0x418) + 6) | 0x4000
        ;
        *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) = *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) | 0x4000
        ;
      }
      else {
        FUN_8022ad34((uint)param_9,iVar7);
        if ((param_9[3] & 0x4000) == 0) {
          *(ushort *)(*(int *)(iVar7 + 0x418) + 6) =
               *(ushort *)(*(int *)(iVar7 + 0x418) + 6) & 0xbfff;
          param_3 = (double)FLOAT_803e7c94;
          local_140 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(iVar7 + 0x418) + 0x36));
          fVar2 = (float)(param_3 * (double)FLOAT_803dc074 +
                         (double)(float)(local_140 - DOUBLE_803e7b80));
          if (FLOAT_803e7c98 < fVar2) {
            fVar2 = FLOAT_803e7c98;
          }
          *(char *)(*(int *)(iVar7 + 0x418) + 0x36) = (char)(int)fVar2;
          *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) =
               *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) & 0xbfff;
          *(char *)(*(int *)(iVar7 + 0x41c) + 0x36) = (char)(int)fVar2;
        }
        else {
          *(undefined2 *)(iVar7 + 0x3f8) = 0;
          *(undefined2 *)(iVar7 + 0x3f4) = 0;
          *(ushort *)(*(int *)(iVar7 + 0x418) + 6) =
               *(ushort *)(*(int *)(iVar7 + 0x418) + 6) | 0x4000;
          *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) =
               *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) | 0x4000;
        }
        *(float *)(iVar7 + 0x3c) = -*(float *)(iVar7 + 0x3e4) * *(float *)(iVar7 + 0x54);
        *(float *)(iVar7 + 0x40) = -*(float *)(iVar7 + 1000) * *(float *)(iVar7 + 0x58);
        *(float *)(iVar7 + 0x44) = *(float *)(iVar7 + 0x5c) * *(float *)(iVar7 + 0x6c);
        iVar1 = (int)(-*(float *)(iVar7 + 0x3e4) * *(float *)(iVar7 + 0x348));
        local_138 = (longlong)iVar1;
        *(int *)(iVar7 + 0x340) = iVar1;
        iVar1 = (int)(*(float *)(iVar7 + 1000) * *(float *)(iVar7 + 0x35c));
        local_140 = (double)(longlong)iVar1;
        *(int *)(iVar7 + 0x354) = iVar1;
        iVar1 = (int)(*(float *)(iVar7 + 0x3e4) * *(float *)(iVar7 + 0x370));
        local_148 = (double)(longlong)iVar1;
        *(int *)(iVar7 + 0x368) = iVar1;
        dVar8 = (double)*(float *)(iVar7 + 900);
        iVar1 = (int)(dVar8 * (double)(*(float *)(iVar7 + 0x3f0) + *(float *)(iVar7 + 0x3ec)));
        local_130 = (longlong)iVar1;
        *(int *)(iVar7 + 0x37c) = iVar1;
        uVar9 = FUN_8022b590(param_9,iVar7);
        uVar9 = FUN_8022c204(uVar9,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             iVar7);
        FUN_8022bf64(uVar9,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar7);
        dVar8 = DOUBLE_803e7b78;
        uStack_124 = -*(int *)(iVar7 + 0x36c) ^ 0x80000000;
        local_128 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803e7b78) *
                     *(float *)(iVar7 + 0x464));
        local_120 = (longlong)iVar1;
        **(undefined2 **)(iVar7 + 0x454) = (short)iVar1;
        uStack_114 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_118 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_114) - dVar8) *
                     *(float *)(iVar7 + 0x464));
        local_110 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x454) + 4) = (short)iVar1;
        uStack_104 = -*(int *)(iVar7 + 0x36c) ^ 0x80000000;
        local_108 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_104) - dVar8) *
                     *(float *)(iVar7 + 0x464));
        local_100 = (longlong)iVar1;
        **(undefined2 **)(iVar7 + 0x458) = (short)iVar1;
        uStack_f4 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_f8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_f4) - dVar8) *
                     *(float *)(iVar7 + 0x464));
        local_f0 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x458) + 4) = (short)iVar1;
        uStack_e4 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_e8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_e4) - dVar8) *
                     *(float *)(iVar7 + 0x464));
        local_e0 = (longlong)iVar1;
        uVar5 = (undefined2)iVar1;
        *(undefined2 *)(*(int *)(iVar7 + 0x45c) + 4) = uVar5;
        **(undefined2 **)(iVar7 + 0x45c) = uVar5;
        uStack_d4 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_d8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_d4) - dVar8) *
                     *(float *)(iVar7 + 0x464));
        local_d0 = (longlong)iVar1;
        uVar5 = (undefined2)iVar1;
        *(undefined2 *)(*(int *)(iVar7 + 0x460) + 4) = uVar5;
        **(undefined2 **)(iVar7 + 0x460) = uVar5;
        uStack_c4 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_c8 = 0x43300000;
        uStack_bc = (int)**(short **)(iVar7 + 0x454) ^ 0x80000000;
        local_c0 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_c4) - dVar8) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack_bc) - dVar8));
        local_b8 = (longlong)iVar1;
        **(short **)(iVar7 + 0x454) = (short)iVar1;
        uStack_ac = *(uint *)(iVar7 + 0x358) ^ 0x80000000;
        local_b0 = 0x43300000;
        uStack_a4 = (int)*(short *)(*(int *)(iVar7 + 0x454) + 4) ^ 0x80000000;
        local_a8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_ac) - dVar8) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack_a4) - dVar8));
        local_a0 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x454) + 4) = (short)iVar1;
        uStack_94 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_98 = 0x43300000;
        uStack_8c = (int)**(short **)(iVar7 + 0x458) ^ 0x80000000;
        local_90 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_94) - dVar8) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack_8c) - dVar8));
        local_88 = (longlong)iVar1;
        **(short **)(iVar7 + 0x458) = (short)iVar1;
        uStack_7c = *(uint *)(iVar7 + 0x358) ^ 0x80000000;
        local_80 = 0x43300000;
        uStack_74 = (int)*(short *)(*(int *)(iVar7 + 0x458) + 4) ^ 0x80000000;
        local_78 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_7c) - dVar8) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack_74) - dVar8));
        local_70 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x458) + 4) = (short)iVar1;
        uStack_64 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_68 = 0x43300000;
        uStack_5c = (int)**(short **)(iVar7 + 0x45c) ^ 0x80000000;
        local_60 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_64) - dVar8) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar8));
        local_58 = (longlong)iVar1;
        **(short **)(iVar7 + 0x45c) = (short)iVar1;
        uStack_4c = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_50 = 0x43300000;
        uStack_44 = (int)*(short *)(*(int *)(iVar7 + 0x45c) + 4) ^ 0x80000000;
        local_48 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_4c) - dVar8) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack_44) - dVar8));
        local_40 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x45c) + 4) = (short)iVar1;
        uStack_34 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_38 = 0x43300000;
        uStack_2c = (int)**(short **)(iVar7 + 0x460) ^ 0x80000000;
        local_30 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_34) - dVar8) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar8));
        local_28 = (longlong)iVar1;
        **(short **)(iVar7 + 0x460) = (short)iVar1;
        uStack_1c = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_20 = 0x43300000;
        dVar11 = (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - dVar8);
        dVar10 = (double)*(float *)(iVar7 + 0x464);
        uStack_14 = (int)*(short *)(*(int *)(iVar7 + 0x460) + 4) ^ 0x80000000;
        local_18 = 0x43300000;
        iVar1 = (int)(dVar11 * dVar10 +
                     (double)(float)((double)CONCAT44(0x43300000,uStack_14) - dVar8));
        local_10 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x460) + 4) = (short)iVar1;
      }
      FUN_8022c9d0((uint)param_9,iVar7);
      (**(code **)(*DAT_803dd6d0 + 0x60))(iVar7 + 0x2c,0xc);
      local_150 = *param_9;
      local_14e = param_9[1];
      local_14c = (undefined2)*(undefined4 *)(iVar7 + 0x36c);
      (**(code **)(*DAT_803dd6d0 + 0x60))(&local_150,6);
      local_158 = *(undefined4 *)(iVar7 + 0x5c);
      local_154 = *(undefined4 *)(iVar7 + 0x50);
      uVar9 = (**(code **)(*DAT_803dd6d0 + 0x60))(&local_158,8);
      uVar9 = FUN_8022c4d8(uVar9,dVar10,dVar11,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                           ,iVar7);
      FUN_8022c794(uVar9,dVar10,dVar11,param_4,param_5,param_6,param_7,param_8,(uint)param_9,iVar7);
      FUN_8022c394(param_9,iVar7);
    }
  }
  return;
}

