// Function: FUN_8029dc20
// Entry: 8029dc20
// Size: 816 bytes

/* WARNING: Removing unreachable block (ram,0x8029df2c) */
/* WARNING: Removing unreachable block (ram,0x8029dc30) */

undefined4
FUN_8029dc20(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  ushort uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 != 199) {
    if (sVar1 < 199) {
      if (sVar1 != 0xc5) {
        if (0xc4 < sVar1) {
          *(float *)(param_10 + 0x2a0) = FLOAT_803e8c04;
          if (*(char *)(param_10 + 0x346) != '\0') {
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,200,0,param_12,param_13,param_14,param_15,param_16);
          }
          fVar2 = FLOAT_803e8b3c;
          *(float *)(param_9 + 0x24) = FLOAT_803e8b3c;
          *(float *)(param_9 + 0x2c) = fVar2;
          goto LAB_8029dee8;
        }
        if (0xc3 < sVar1) {
          *(float *)(param_10 + 0x2a0) = FLOAT_803e8c04;
          if ((*(float *)(param_9 + 0x28) < FLOAT_803e8b78) && ((*(byte *)(iVar6 + 0x3f1) & 1) != 0)
             ) {
            if (*(short *)(iVar6 + 0x81a) == 0) {
              uVar3 = 0x2d2;
            }
            else {
              uVar3 = 0x214;
            }
            FUN_8000bb38(param_9,uVar3);
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0xc6,0,param_12,param_13,param_14,param_15,param_16);
          }
          if (FLOAT_803e8b78 <
              *(float *)(param_9 + 0x24) * *(float *)(param_9 + 0x24) +
              *(float *)(param_9 + 0x2c) * *(float *)(param_9 + 0x2c)) {
            uVar4 = FUN_80021884();
            iVar5 = (uVar4 & 0xffff) - (uint)*(ushort *)(iVar6 + 0x478);
            if (0x8000 < iVar5) {
              iVar5 = iVar5 + -0xffff;
            }
            if (iVar5 < -0x8000) {
              iVar5 = iVar5 + 0xffff;
            }
            *(short *)(iVar6 + 0x478) =
                 *(short *)(iVar6 + 0x478) + (short)(iVar5 * (int)param_1 >> 3);
            *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
          }
          goto LAB_8029dee8;
        }
      }
    }
    else {
      if (sVar1 == 0x450) {
        *(float *)(param_10 + 0x2a0) = FLOAT_803e8c64;
        if ((*(float *)(param_9 + 0x28) < FLOAT_803e8b78) && ((*(byte *)(iVar6 + 0x3f1) & 1) != 0))
        {
          if (*(short *)(iVar6 + 0x81a) == 0) {
            uVar3 = 0x2d2;
          }
          else {
            uVar3 = 0x214;
          }
          FUN_8000bb38(param_9,uVar3);
          FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,0xc6,0,param_12,param_13,param_14,param_15,param_16);
        }
        if (FLOAT_803e8b78 <
            *(float *)(param_9 + 0x24) * *(float *)(param_9 + 0x24) +
            *(float *)(param_9 + 0x2c) * *(float *)(param_9 + 0x2c)) {
          uVar4 = FUN_80021884();
          iVar5 = (uVar4 & 0xffff) - (uint)*(ushort *)(iVar6 + 0x478);
          if (0x8000 < iVar5) {
            iVar5 = iVar5 + -0xffff;
          }
          if (iVar5 < -0x8000) {
            iVar5 = iVar5 + 0xffff;
          }
          *(short *)(iVar6 + 0x478) = *(short *)(iVar6 + 0x478) + (short)(iVar5 * (int)param_1 >> 3)
          ;
          *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
        }
        goto LAB_8029dee8;
      }
      if ((sVar1 < 0x450) && (sVar1 < 0xc9)) {
        *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
        if (*(char *)(param_10 + 0x346) != '\0') {
          *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x800000;
          *(code **)(param_10 + 0x308) = FUN_802a58ac;
          return 0xffffffff;
        }
        goto LAB_8029dee8;
      }
    }
  }
  FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0xc4,0,param_12,param_13,param_14,param_15,param_16);
LAB_8029dee8:
  *(byte *)(param_10 + 0x34c) = *(byte *)(param_10 + 0x34c) | 2;
  dVar7 = (double)FUN_802932a4((double)FLOAT_803e8c68,param_1);
  *(float *)(param_9 + 0x24) = (float)((double)*(float *)(param_9 + 0x24) * dVar7);
  dVar7 = (double)FUN_802932a4((double)FLOAT_803e8c68,param_1);
  *(float *)(param_9 + 0x2c) = (float)((double)*(float *)(param_9 + 0x2c) * dVar7);
  return 0;
}

