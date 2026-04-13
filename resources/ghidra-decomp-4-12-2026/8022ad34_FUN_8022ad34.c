// Function: FUN_8022ad34
// Entry: 8022ad34
// Size: 856 bytes

/* WARNING: Removing unreachable block (ram,0x8022b06c) */
/* WARNING: Removing unreachable block (ram,0x8022b064) */
/* WARNING: Removing unreachable block (ram,0x8022b05c) */
/* WARNING: Removing unreachable block (ram,0x8022ad54) */
/* WARNING: Removing unreachable block (ram,0x8022ad4c) */
/* WARNING: Removing unreachable block (ram,0x8022ad44) */

void FUN_8022ad34(uint param_1,int param_2)

{
  float fVar1;
  float fVar2;
  char cVar4;
  uint uVar3;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 local_40;
  
  FUN_801378a8(0xff,0xff,0xff,0xff);
  cVar4 = FUN_80014cec(0);
  *(float *)(param_2 + 0x3e4) =
       (float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) - DOUBLE_803e7b78) /
       FLOAT_803e7b60;
  cVar4 = FUN_80014c98(0);
  local_40 = (double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000);
  *(float *)(param_2 + 1000) = (float)(local_40 - DOUBLE_803e7b78) / FLOAT_803e7b60;
  fVar1 = FLOAT_803e7b64;
  if (FLOAT_803e7b64 < *(float *)(param_2 + 0x328)) {
    dVar8 = -(double)*(float *)(param_2 + 0x32c);
    dVar7 = -(double)*(float *)(param_2 + 0x330);
    *(float *)(param_2 + 0x328) = *(float *)(param_2 + 0x328) - FLOAT_803dc074;
    dVar6 = (double)*(float *)(&DAT_8032c100 + (int)*(float *)(param_2 + 0x328) * 4);
    if (*(float *)(param_2 + 0x328) <= fVar1) {
      *(undefined *)(param_2 + 0x338) = 0;
      (**(code **)(*DAT_803dd728 + 0x20))(param_1,param_2 + 0xc0);
    }
    dVar5 = (double)FLOAT_803e7b68;
    *(float *)(param_2 + 0x3e4) =
         *(float *)(param_2 + 0x3e4) * (float)(dVar5 - dVar6) + (float)(dVar8 * dVar6);
    *(float *)(param_2 + 1000) =
         *(float *)(param_2 + 1000) * (float)(dVar5 - dVar6) + (float)(dVar7 * dVar6);
  }
  uVar3 = FUN_80014d84(0);
  local_40 = (double)CONCAT44(0x43300000,uVar3 & 0xff);
  *(float *)(param_2 + 0x3ec) = (float)(local_40 - DOUBLE_803e7b80) / FLOAT_803e7b6c;
  fVar1 = *(float *)(param_2 + 0x3ec);
  fVar2 = FLOAT_803e7b64;
  if ((FLOAT_803e7b64 <= fVar1) && (fVar2 = fVar1, FLOAT_803e7b68 < fVar1)) {
    fVar2 = FLOAT_803e7b68;
  }
  *(float *)(param_2 + 0x3ec) = fVar2;
  uVar3 = FUN_80014d40(0);
  *(float *)(param_2 + 0x3f0) =
       -(float)((double)CONCAT44(0x43300000,uVar3 & 0xff) - DOUBLE_803e7b80) / FLOAT_803e7b6c;
  fVar1 = *(float *)(param_2 + 0x3f0);
  fVar2 = FLOAT_803e7b70;
  if ((FLOAT_803e7b70 <= fVar1) && (fVar2 = fVar1, FLOAT_803e7b64 < fVar1)) {
    fVar2 = FLOAT_803e7b64;
  }
  *(float *)(param_2 + 0x3f0) = fVar2;
  uVar3 = FUN_80014e9c(0);
  *(short *)(param_2 + 0x3f4) = (short)uVar3;
  uVar3 = FUN_80014e40(0);
  *(short *)(param_2 + 0x3f6) = (short)uVar3;
  uVar3 = FUN_80014f14(0);
  *(short *)(param_2 + 0x3f8) = (short)uVar3;
  if (*(char *)(param_2 + 0x478) == '\0') {
    if ((*(ushort *)(param_2 + 0x3f4) & 0x20) == 0) {
      if ((*(ushort *)(param_2 + 0x3f4) & 0x40) != 0) {
        FUN_8000bb38(param_1,0x2a4);
        *(undefined *)(param_2 + 0x478) = 1;
        *(int *)(param_2 + 0x398) = (int)*(short *)(param_1 + 4);
        *(float *)(param_2 + 0x3a0) = -*(float *)(param_2 + 0x39c);
        *(float *)(param_2 + 0x3a8) = FLOAT_803e7b68;
        *(float *)(param_2 + 0x54) = *(float *)(param_2 + 0x54) * *(float *)(param_2 + 0x3ac);
        *(float *)(param_2 + 0x60) = *(float *)(param_2 + 0x60) * *(float *)(param_2 + 0x3b0);
        FUN_8022f80c(*(int *)(param_2 + 0x10),'\x01','\x01');
      }
    }
    else {
      FUN_8000bb38(param_1,0x2a4);
      *(undefined *)(param_2 + 0x478) = 1;
      *(int *)(param_2 + 0x398) = (int)*(short *)(param_1 + 4);
      *(undefined4 *)(param_2 + 0x3a0) = *(undefined4 *)(param_2 + 0x39c);
      *(float *)(param_2 + 0x3a8) = FLOAT_803e7b68;
      *(float *)(param_2 + 0x54) = *(float *)(param_2 + 0x54) * *(float *)(param_2 + 0x3ac);
      *(float *)(param_2 + 0x60) = *(float *)(param_2 + 0x60) * *(float *)(param_2 + 0x3b0);
      FUN_8022f80c(*(int *)(param_2 + 0x10),'\x01','\0');
    }
  }
  return;
}

