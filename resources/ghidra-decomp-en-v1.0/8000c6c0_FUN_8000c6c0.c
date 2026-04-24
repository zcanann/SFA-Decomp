// Function: FUN_8000c6c0
// Entry: 8000c6c0
// Size: 748 bytes

/* WARNING: Removing unreachable block (ram,0x8000c980) */
/* WARNING: Removing unreachable block (ram,0x8000c970) */
/* WARNING: Removing unreachable block (ram,0x8000c978) */
/* WARNING: Removing unreachable block (ram,0x8000c988) */

void FUN_8000c6c0(undefined4 *param_1)

{
  float fVar1;
  uint uVar2;
  short *psVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f28;
  double dVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack100;
  double local_60;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  psVar3 = (short *)FUN_8000faac();
  if (((psVar3 != (short *)0x0) && (param_1 != (undefined4 *)0x0)) &&
     (*(char *)(param_1 + 1) != '\0')) {
    uStack100 = (uint)*(byte *)((int)param_1 + 7);
    local_68 = 0x43300000;
    dVar7 = (double)CONCAT44(0x43300000,uStack100) - DOUBLE_803de588;
    dVar8 = (double)(float)dVar7;
    uVar5 = (uint)dVar7;
    local_60 = (double)(longlong)(int)uVar5;
    dVar10 = (double)(float)param_1[8];
    dVar9 = (double)(float)param_1[9];
    dVar7 = (double)FUN_8000cbc0(param_1 + 3,&local_78);
    if (dVar7 <= (double)(float)((double)FLOAT_803de598 * dVar9)) {
      FUN_8000c9ac(0,0,(int)-psVar3[0x2a],&local_78);
      FUN_8000c9ac((int)*psVar3,0,0,&local_78);
      FUN_8000c9ac(0,(int)-psVar3[0x29],0,&local_78);
      if (dVar7 <= (double)FLOAT_803de59c) {
        if (*(char *)((int)param_1 + 6) != '\0') {
          uVar5 = 0;
        }
        FUN_802727a8(*param_1,7,uVar5 & 0xff);
      }
      else {
        if (dVar10 <= dVar7) {
          if (dVar7 <= dVar9) {
            uVar5 = (uint)(dVar8 * (double)(FLOAT_803de574 -
                                           (float)(dVar7 - dVar10) / (float)(dVar9 - dVar10)));
            if ((int)uVar5 < 1) {
              uVar5 = 1;
            }
            else {
              local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
              if (dVar8 < (double)(float)(local_60 - DOUBLE_803de580)) {
                uVar5 = (uint)dVar8;
              }
            }
          }
          else {
            uVar5 = 1;
          }
        }
        else {
          uVar5 = (uint)dVar8;
        }
        fVar1 = (float)((double)FLOAT_803de5a0 / dVar7);
        local_78 = local_78 * fVar1;
        local_74 = local_74 * fVar1;
        local_70 = local_70 * fVar1;
        uVar2 = (uint)(FLOAT_803de5a8 * local_78 + FLOAT_803de5a4);
        if ((int)uVar2 < 0x80) {
          if ((int)uVar2 < 0) {
            uVar2 = 0;
          }
        }
        else {
          uVar2 = 0x7f;
        }
        uVar4 = (uint)(FLOAT_803de5a8 * local_70 + FLOAT_803de5a4);
        local_60 = (double)(longlong)(int)uVar4;
        if ((int)uVar4 < 0x80) {
          if ((int)uVar4 < 0) {
            uVar4 = 0;
          }
        }
        else {
          uVar4 = 0x7f;
        }
        FUN_802727a8(*param_1,10,uVar2 & 0xff);
        FUN_802727a8(*param_1,0x83,uVar4 & 0xff);
        if (*(char *)((int)param_1 + 6) != '\0') {
          uVar5 = 0;
        }
        FUN_802727a8(*param_1,7,uVar5 & 0xff);
      }
    }
    else {
      FUN_80272868(*param_1);
      *param_1 = 0xffffffff;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  return;
}

