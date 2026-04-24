// Function: FUN_801b3de4
// Entry: 801b3de4
// Size: 724 bytes

/* WARNING: Removing unreachable block (ram,0x801b4098) */

void FUN_801b3de4(undefined8 param_1,double param_2,double param_3,double param_4)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  undefined2 uVar5;
  undefined uVar6;
  undefined extraout_r4;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined4 uVar12;
  double extraout_f1;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  double local_68;
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_802860d8();
  iVar8 = *(int *)(iVar4 + 0x4c);
  iVar9 = *(int *)(iVar4 + 0xb8);
  bVar1 = *(byte *)(iVar9 + 0xa58);
  *(byte *)(iVar9 + 0xa58) = bVar1 + 1;
  iVar10 = (uint)bVar1 * 0x30;
  *(float *)(iVar9 + iVar10) = (float)param_2;
  iVar11 = iVar9 + iVar10;
  *(float *)(iVar11 + 4) = (float)param_3;
  *(float *)(iVar11 + 8) = (float)param_4;
  *(float *)(iVar11 + 0x18) = FLOAT_803e492c;
  *(undefined4 *)(iVar11 + 0xc) = *(undefined4 *)(iVar9 + 0x18);
  *(float *)(iVar11 + 0x1c) = (float)extraout_f1;
  *(undefined *)(iVar11 + 0x2d) = extraout_r4;
  *(undefined4 *)(iVar11 + 0x10) = 0;
  dVar13 = (double)FUN_802931a0();
  *(int *)(iVar11 + 0x14) = (int)((double)FLOAT_803e4930 * dVar13);
  iVar3 = *(int *)(iVar11 + 0x14);
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (0x3c < iVar3) {
    iVar3 = 0x3c;
  }
  *(int *)(iVar11 + 0x14) = iVar3;
  if ((*(char *)(iVar11 + 0x2d) != '\0') || (cVar2 = *(char *)(iVar8 + 0x19), cVar2 == '\0'))
  goto LAB_801b3f20;
  if (cVar2 == '\x02') {
    FUN_8000bb18(iVar4,0x4bf);
    goto LAB_801b3f20;
  }
  if (cVar2 == '\x03') {
    FUN_8000bb18(iVar4,0x4c2);
    goto LAB_801b3f20;
  }
  cVar2 = *(char *)(iVar4 + 0xac);
  if (cVar2 < ':') {
    if (cVar2 == ',') {
LAB_801b3f00:
      FUN_8000b4d0(iVar4,0x4b8,2);
      goto LAB_801b3f20;
    }
  }
  else if (cVar2 < '?') goto LAB_801b3f00;
  FUN_8000bb18(iVar4,0x203);
LAB_801b3f20:
  uVar5 = FUN_800221a0(0,0xffff);
  *(undefined2 *)(iVar9 + iVar10 + 0x28) = uVar5;
  uVar5 = FUN_800221a0(200,300);
  iVar4 = iVar9 + iVar10;
  *(undefined2 *)(iVar4 + 0x2a) = uVar5;
  iVar3 = FUN_800221a0(0,1);
  if (iVar3 != 0) {
    *(short *)(iVar4 + 0x2a) = -*(short *)(iVar4 + 0x2a);
  }
  uVar6 = FUN_800221a0(0,3);
  *(undefined *)(iVar9 + iVar10 + 0x2c) = uVar6;
  dVar14 = (double)*(float *)(iVar11 + 0x1c);
  uVar7 = *(uint *)(iVar11 + 0x14) ^ 0x80000000;
  local_68 = (double)CONCAT44(0x43300000,uVar7);
  dVar13 = (double)FUN_80291dd8((double)((FLOAT_803e4934 *
                                         ((float)(local_68 - DOUBLE_803e4948) -
                                         (float)((double)CONCAT44(0x43300000,
                                                                  *(uint *)(iVar11 + 0x10) ^
                                                                  0x80000000) - DOUBLE_803e4948))) /
                                        (float)((double)CONCAT44(0x43300000,uVar7) - DOUBLE_803e4948
                                               )));
  *(float *)(iVar11 + 0xc) =
       -(float)((double)FLOAT_803ddb70 *
                (double)(float)((double)(float)(dVar14 - (double)*(float *)(iVar11 + 0x18)) * dVar13
                               ) - dVar14);
  dVar13 = (double)FUN_80291dd8((double)((FLOAT_803e493c *
                                         (float)((double)CONCAT44(0x43300000,
                                                                  *(uint *)(iVar11 + 0x10) ^
                                                                  0x80000000) - DOUBLE_803e4948)) /
                                        (float)((double)CONCAT44(0x43300000,
                                                                 *(uint *)(iVar11 + 0x14) ^
                                                                 0x80000000) - DOUBLE_803e4948)));
  iVar9 = iVar9 + iVar10;
  *(char *)(iVar9 + 0x2e) =
       (char)(int)-(float)((double)FLOAT_803ddb6c * (double)(float)((double)FLOAT_803e4938 * dVar13)
                          - (double)FLOAT_803e4938);
  *(int *)(iVar9 + 0x20) = (int)FLOAT_803e4940;
  *(undefined4 *)(iVar9 + 0x24) = *(undefined4 *)(iVar9 + 0x20);
  *(undefined *)(iVar9 + 0x2f) = 1;
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  FUN_80286124();
  return;
}

