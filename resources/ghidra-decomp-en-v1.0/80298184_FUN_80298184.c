// Function: FUN_80298184
// Entry: 80298184
// Size: 508 bytes

/* WARNING: Removing unreachable block (ram,0x8029835c) */

int FUN_80298184(undefined8 param_1,undefined2 *param_2,int param_3)

{
  undefined2 uVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *(int *)(param_2 + 0x5c);
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800;
  if (*(char *)(param_3 + 0x27a) != '\0') {
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
    fVar2 = FLOAT_803e7ea4;
    *(float *)(param_3 + 0x294) = FLOAT_803e7ea4;
    *(float *)(param_3 + 0x284) = fVar2;
    *(float *)(param_3 + 0x280) = fVar2;
    *(float *)(param_2 + 0x12) = fVar2;
    *(float *)(param_2 + 0x14) = fVar2;
    *(float *)(param_2 + 0x16) = fVar2;
  }
  iVar3 = FUN_8029b9fc(param_1,param_2,param_3);
  if (iVar3 == 0) {
    (**(code **)(*DAT_803dca8c + 0x30))(param_1,param_2,param_3,1);
    uVar1 = *param_2;
    *(undefined2 *)(iVar5 + 0x484) = uVar1;
    *(undefined2 *)(iVar5 + 0x478) = uVar1;
    uVar4 = FUN_80014dd8(0);
    if ((uVar4 & 0x20) == 0) {
      *(code **)(param_3 + 0x308) = FUN_8029c8c8;
      iVar3 = 0x25;
    }
    else {
      if (*(char *)(param_3 + 0x27a) != '\0') {
        *(byte *)(iVar5 + 0x3f6) = *(byte *)(iVar5 + 0x3f6) & 0xef;
      }
      if ((*(byte *)(iVar5 + 0x3f6) >> 4 & 1) == 0) {
        *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
        if ((param_2[0x50] != 0x458) && (iVar3 = FUN_8002f50c(param_2), iVar3 == 0)) {
          FUN_80030334((double)*(float *)(param_2 + 0x4c),param_2,0x458,0);
          FUN_8002f574(param_2,8);
        }
      }
      else {
        *(float *)(param_3 + 0x2a0) = FLOAT_803e7e8c;
        if (param_2[0x50] != 0x455) {
          FUN_80014aa0((double)FLOAT_803e7ed8);
          FUN_80030334((double)FLOAT_803e7ea4,param_2,0x455,0);
          *(float *)(param_3 + 0x280) = -*(float *)(iVar5 + 0x88c);
        }
        if (*(char *)(param_3 + 0x346) != '\0') {
          *(byte *)(iVar5 + 0x3f6) = *(byte *)(iVar5 + 0x3f6) & 0xef;
        }
      }
      dVar7 = (double)FUN_80292b44((double)*(float *)(iVar5 + 0x888),(double)FLOAT_803db414);
      *(float *)(param_3 + 0x280) = (float)((double)*(float *)(param_3 + 0x280) * dVar7);
      iVar3 = 0;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return iVar3;
}

