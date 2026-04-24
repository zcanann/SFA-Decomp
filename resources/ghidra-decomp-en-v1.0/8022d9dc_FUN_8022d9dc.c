// Function: FUN_8022d9dc
// Entry: 8022d9dc
// Size: 2180 bytes

void FUN_8022d9dc(undefined2 *param_1)

{
  int iVar1;
  char cVar2;
  float fVar3;
  double dVar4;
  undefined4 uVar5;
  undefined2 uVar6;
  int iVar7;
  undefined4 local_158;
  undefined4 local_154;
  undefined2 local_150;
  undefined2 local_14e;
  undefined2 local_14c;
  double local_148;
  double local_140;
  longlong local_138;
  longlong local_130;
  undefined4 local_128;
  uint uStack292;
  longlong local_120;
  undefined4 local_118;
  uint uStack276;
  longlong local_110;
  undefined4 local_108;
  uint uStack260;
  longlong local_100;
  undefined4 local_f8;
  uint uStack244;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack228;
  longlong local_e0;
  undefined4 local_d8;
  uint uStack212;
  longlong local_d0;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  longlong local_b8;
  undefined4 local_b0;
  uint uStack172;
  undefined4 local_a8;
  uint uStack164;
  longlong local_a0;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  longlong local_88;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  longlong local_70;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  longlong local_10;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  if ((*(byte *)(iVar7 + 0x477) & 1) == 0) {
    FUN_8022cdec(param_1,iVar7);
  }
  else {
    cVar2 = *(char *)(iVar7 + 0x478);
    if (cVar2 == '\x05') {
      fVar3 = *(float *)(iVar7 + 0x46c) - FLOAT_803db414;
      *(float *)(iVar7 + 0x46c) = fVar3;
      if (fVar3 <= FLOAT_803e6ecc) {
        *(undefined *)(iVar7 + 0x478) = 6;
        (**(code **)(*DAT_803dca4c + 8))(0x14,1);
        *(float *)(iVar7 + 0x46c) = FLOAT_803e6f34;
      }
    }
    else if (cVar2 == '\x06') {
      fVar3 = *(float *)(iVar7 + 0x46c) - FLOAT_803db414;
      *(float *)(iVar7 + 0x46c) = fVar3;
      if (fVar3 <= FLOAT_803e6ecc) {
        if (*(char *)(param_1 + 0x56) == '&') {
          FUN_8004350c(0,0,1);
          uVar5 = FUN_800481b0(0x26);
          FUN_80043560(uVar5,0);
          uVar5 = FUN_800481b0(0xb);
          FUN_80043560(uVar5,1);
          FUN_800552e8(0x32,0);
        }
        else {
          FUN_800552e8(0x60,0);
        }
      }
    }
    else {
      if (cVar2 == '\x04') {
        fVar3 = *(float *)(iVar7 + 0x46c) - FLOAT_803db414;
        *(float *)(iVar7 + 0x46c) = fVar3;
        if (fVar3 <= FLOAT_803e6ecc) {
          *(undefined *)(iVar7 + 0x478) = 5;
          *(float *)(iVar7 + 0x46c) = FLOAT_803e6f24;
          param_1[3] = param_1[3] | 0x4000;
          FUN_8009ab70((double)FLOAT_803e6f28,param_1,1,0,1,1,0,1,0);
        }
        local_148 = (double)CONCAT44(0x43300000,*(uint *)(iVar7 + 0x36c) ^ 0x80000000);
        iVar1 = (int)(FLOAT_803e6f6c * FLOAT_803db414 + (float)(local_148 - DOUBLE_803e6ee0));
        local_140 = (double)(longlong)iVar1;
        *(int *)(iVar7 + 0x36c) = iVar1;
        param_1[2] = (short)*(undefined4 *)(iVar7 + 0x36c);
        *(float *)(iVar7 + 0x4c) = -(FLOAT_803e6ef8 * FLOAT_803db414 - *(float *)(iVar7 + 0x4c));
        FUN_8002b95c((double)(*(float *)(iVar7 + 0x48) * FLOAT_803db414),
                     (double)(*(float *)(iVar7 + 0x4c) * FLOAT_803db414),
                     (double)(*(float *)(iVar7 + 0x50) * FLOAT_803db414),param_1);
        FUN_8022ae1c(param_1,iVar7);
        *(ushort *)(*(int *)(iVar7 + 0x418) + 6) = *(ushort *)(*(int *)(iVar7 + 0x418) + 6) | 0x4000
        ;
        *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) = *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) | 0x4000
        ;
      }
      else {
        FUN_8022a670(param_1,iVar7);
        if ((param_1[3] & 0x4000) == 0) {
          *(ushort *)(*(int *)(iVar7 + 0x418) + 6) =
               *(ushort *)(*(int *)(iVar7 + 0x418) + 6) & 0xbfff;
          local_140 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(iVar7 + 0x418) + 0x36));
          fVar3 = FLOAT_803e6ffc * FLOAT_803db414 + (float)(local_140 - DOUBLE_803e6ee8);
          if (FLOAT_803e7000 < fVar3) {
            fVar3 = FLOAT_803e7000;
          }
          *(char *)(*(int *)(iVar7 + 0x418) + 0x36) = (char)(int)fVar3;
          *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) =
               *(ushort *)(*(int *)(iVar7 + 0x41c) + 6) & 0xbfff;
          *(char *)(*(int *)(iVar7 + 0x41c) + 0x36) = (char)(int)fVar3;
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
        iVar1 = (int)(*(float *)(iVar7 + 900) *
                     (*(float *)(iVar7 + 0x3f0) + *(float *)(iVar7 + 0x3ec)));
        local_130 = (longlong)iVar1;
        *(int *)(iVar7 + 0x37c) = iVar1;
        FUN_8022aecc(param_1,iVar7);
        FUN_8022bb40(param_1,iVar7);
        FUN_8022b8a0(param_1,iVar7);
        dVar4 = DOUBLE_803e6ee0;
        uStack292 = -*(int *)(iVar7 + 0x36c) ^ 0x80000000;
        local_128 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack292) - DOUBLE_803e6ee0) *
                     *(float *)(iVar7 + 0x464));
        local_120 = (longlong)iVar1;
        **(undefined2 **)(iVar7 + 0x454) = (short)iVar1;
        uStack276 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_118 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack276) - dVar4) *
                     *(float *)(iVar7 + 0x464));
        local_110 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x454) + 4) = (short)iVar1;
        uStack260 = -*(int *)(iVar7 + 0x36c) ^ 0x80000000;
        local_108 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack260) - dVar4) *
                     *(float *)(iVar7 + 0x464));
        local_100 = (longlong)iVar1;
        **(undefined2 **)(iVar7 + 0x458) = (short)iVar1;
        uStack244 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_f8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack244) - dVar4) *
                     *(float *)(iVar7 + 0x464));
        local_f0 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x458) + 4) = (short)iVar1;
        uStack228 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_e8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack228) - dVar4) *
                     *(float *)(iVar7 + 0x464));
        local_e0 = (longlong)iVar1;
        uVar6 = (undefined2)iVar1;
        *(undefined2 *)(*(int *)(iVar7 + 0x45c) + 4) = uVar6;
        **(undefined2 **)(iVar7 + 0x45c) = uVar6;
        uStack212 = *(uint *)(iVar7 + 0x36c) ^ 0x80000000;
        local_d8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack212) - dVar4) *
                     *(float *)(iVar7 + 0x464));
        local_d0 = (longlong)iVar1;
        uVar6 = (undefined2)iVar1;
        *(undefined2 *)(*(int *)(iVar7 + 0x460) + 4) = uVar6;
        **(undefined2 **)(iVar7 + 0x460) = uVar6;
        uStack196 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_c8 = 0x43300000;
        uStack188 = (int)**(short **)(iVar7 + 0x454) ^ 0x80000000;
        local_c0 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack196) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack188) - dVar4));
        local_b8 = (longlong)iVar1;
        **(short **)(iVar7 + 0x454) = (short)iVar1;
        uStack172 = *(uint *)(iVar7 + 0x358) ^ 0x80000000;
        local_b0 = 0x43300000;
        uStack164 = (int)*(short *)(*(int *)(iVar7 + 0x454) + 4) ^ 0x80000000;
        local_a8 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack172) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack164) - dVar4));
        local_a0 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x454) + 4) = (short)iVar1;
        uStack148 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_98 = 0x43300000;
        uStack140 = (int)**(short **)(iVar7 + 0x458) ^ 0x80000000;
        local_90 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack148) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack140) - dVar4));
        local_88 = (longlong)iVar1;
        **(short **)(iVar7 + 0x458) = (short)iVar1;
        uStack124 = *(uint *)(iVar7 + 0x358) ^ 0x80000000;
        local_80 = 0x43300000;
        uStack116 = (int)*(short *)(*(int *)(iVar7 + 0x458) + 4) ^ 0x80000000;
        local_78 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack124) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack116) - dVar4));
        local_70 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x458) + 4) = (short)iVar1;
        uStack100 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_68 = 0x43300000;
        uStack92 = (int)**(short **)(iVar7 + 0x45c) ^ 0x80000000;
        local_60 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack100) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack92) - dVar4));
        local_58 = (longlong)iVar1;
        **(short **)(iVar7 + 0x45c) = (short)iVar1;
        uStack76 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_50 = 0x43300000;
        uStack68 = (int)*(short *)(*(int *)(iVar7 + 0x45c) + 4) ^ 0x80000000;
        local_48 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack76) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack68) - dVar4));
        local_40 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x45c) + 4) = (short)iVar1;
        uStack52 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_38 = 0x43300000;
        uStack44 = (int)**(short **)(iVar7 + 0x460) ^ 0x80000000;
        local_30 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack52) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack44) - dVar4));
        local_28 = (longlong)iVar1;
        **(short **)(iVar7 + 0x460) = (short)iVar1;
        uStack28 = -*(int *)(iVar7 + 0x358) ^ 0x80000000;
        local_20 = 0x43300000;
        uStack20 = (int)*(short *)(*(int *)(iVar7 + 0x460) + 4) ^ 0x80000000;
        local_18 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack28) - dVar4) *
                      *(float *)(iVar7 + 0x464) +
                     (float)((double)CONCAT44(0x43300000,uStack20) - dVar4));
        local_10 = (longlong)iVar1;
        *(short *)(*(int *)(iVar7 + 0x460) + 4) = (short)iVar1;
      }
      FUN_8022c30c(param_1,iVar7);
      (**(code **)(*DAT_803dca50 + 0x60))(iVar7 + 0x2c,0xc);
      local_150 = *param_1;
      local_14e = param_1[1];
      local_14c = (undefined2)*(undefined4 *)(iVar7 + 0x36c);
      (**(code **)(*DAT_803dca50 + 0x60))(&local_150,6);
      local_158 = *(undefined4 *)(iVar7 + 0x5c);
      local_154 = *(undefined4 *)(iVar7 + 0x50);
      (**(code **)(*DAT_803dca50 + 0x60))(&local_158,8);
      FUN_8022be14(param_1,iVar7);
      FUN_8022c0d0(param_1,iVar7);
      FUN_8022bcd0(param_1,iVar7);
    }
  }
  return;
}

