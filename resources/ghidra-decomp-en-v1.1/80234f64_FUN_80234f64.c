// Function: FUN_80234f64
// Entry: 80234f64
// Size: 872 bytes

void FUN_80234f64(short *param_1,int param_2)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  undefined4 extraout_r4;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar10;
  double dVar11;
  undefined8 uVar12;
  double dVar13;
  undefined8 in_f4;
  undefined8 in_f5;
  double dVar14;
  undefined8 in_f6;
  double dVar15;
  undefined8 in_f7;
  undefined8 in_f8;
  
  fVar4 = DAT_802c2da0;
  fVar3 = DAT_802c2d9c;
  fVar2 = DAT_802c2d98;
  piVar10 = *(int **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x34) << 8;
  if (*piVar10 == 0) {
    piVar5 = FUN_8001f58c((int)param_1,'\x01');
    *piVar10 = (int)piVar5;
  }
  if (*piVar10 != 0) {
    FUN_8001dbf0(*piVar10,8);
    dVar11 = (double)FLOAT_803e7f08;
    FUN_8001de4c(dVar11,dVar11,dVar11,(int *)*piVar10);
    dVar13 = (double)fVar4;
    FUN_8001dd54((double)fVar2,(double)fVar3,dVar13,(int *)*piVar10);
    uVar7 = (uint)*(byte *)(param_2 + 0x2e);
    uVar8 = (uint)*(byte *)(param_2 + 0x2f);
    uVar9 = (uint)*(byte *)(param_2 + 0x37);
    FUN_8001dbb4(*piVar10,*(undefined *)(param_2 + 0x2d),*(byte *)(param_2 + 0x2e),
                 *(byte *)(param_2 + 0x2f),*(byte *)(param_2 + 0x37));
    dVar11 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1c)) -
                            DOUBLE_803e7f10);
    FUN_8001dcfc((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1a)) -
                                DOUBLE_803e7f10),dVar11,*piVar10);
    FUN_8001dbe8(*piVar10,(uint)*(byte *)(param_2 + 0x39));
    uVar12 = FUN_8001dc30((double)FLOAT_803e7f08,*piVar10,*(char *)(param_2 + 0x3a));
    if (piVar10[1] == 0) {
      if (*(ushort *)(param_2 + 0x24) == 0) {
        iVar6 = FUN_80054ed0(uVar12,dVar11,dVar13,in_f4,in_f5,in_f6,in_f7,in_f8,0x5dc,extraout_r4,
                             uVar7,uVar8,uVar9,in_r8,in_r9,in_r10);
        piVar10[1] = iVar6;
      }
      else {
        iVar6 = FUN_80054ed0(uVar12,dVar11,dVar13,in_f4,in_f5,in_f6,in_f7,in_f8,
                             (uint)*(ushort *)(param_2 + 0x24),extraout_r4,uVar7,uVar8,uVar9,in_r8,
                             in_r9,in_r10);
        piVar10[1] = iVar6;
      }
      FUN_8001da50(*piVar10,piVar10[1]);
    }
    if (*(char *)(param_2 + 0x26) == '\0') {
      dVar11 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x28)) -
                               DOUBLE_803e7f10) / FLOAT_803e7f0c);
      if (dVar11 < (double)FLOAT_803e7ef8) {
        dVar11 = (double)FLOAT_803e7ef8;
      }
      dVar13 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a)) -
                               DOUBLE_803e7f10) / FLOAT_803e7f0c);
      if (dVar13 < (double)FLOAT_803e7ef8) {
        dVar13 = (double)FLOAT_803e7ef8;
      }
      bVar1 = *(byte *)(param_2 + 0x3f);
      if (bVar1 == 0) {
        dVar14 = (double)FLOAT_803e7ef8;
        dVar15 = dVar14;
      }
      else {
        dVar14 = (double)(float)((double)CONCAT44(0x43300000,bVar1 & 0xf ^ 0x80000000) -
                                DOUBLE_803e7f00);
        dVar15 = (double)(float)((double)CONCAT44(0x43300000,bVar1 >> 4 ^ 0x80000000) -
                                DOUBLE_803e7f00);
      }
      FUN_8001d9b4(dVar13,-dVar13,-dVar11,dVar11,dVar14,dVar15,*piVar10);
    }
    else {
      fVar2 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x28)) -
                     DOUBLE_803e7f10) / FLOAT_803e7f0c;
      if (fVar2 < FLOAT_803e7ef8) {
        fVar2 = FLOAT_803e7ef8;
      }
      fVar3 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a)) -
                     DOUBLE_803e7f10) / FLOAT_803e7f0c;
      if (fVar3 < FLOAT_803e7ef8) {
        fVar3 = FLOAT_803e7ef8;
      }
      FUN_8001d93c((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x27)) -
                                  DOUBLE_803e7f10),(double)(fVar2 / fVar3),*piVar10);
    }
    FUN_8001d8d0(*piVar10,(uint)*(byte *)(param_2 + 0x36),(uint)*(byte *)(param_2 + 0x3e));
    FUN_8001d910((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x3b)) -
                                DOUBLE_803e7f10),*piVar10);
    FUN_8001d8e4((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3c)) -
                                DOUBLE_803e7f10),*piVar10);
    FUN_8001d6e4(*piVar10,(uint)*(byte *)(param_2 + 0x33),*(short *)(param_2 + 0x1e));
    FUN_8001db7c(*piVar10,*(undefined *)(param_2 + 0x30),*(undefined *)(param_2 + 0x31),
                 *(undefined *)(param_2 + 0x32),*(undefined *)(param_2 + 0x38));
  }
  return;
}

