// Function: FUN_802348a0
// Entry: 802348a0
// Size: 872 bytes

void FUN_802348a0(short *param_1,int param_2)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  
  fVar4 = DAT_802c2620;
  fVar3 = DAT_802c261c;
  fVar2 = DAT_802c2618;
  piVar6 = *(int **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x34) << 8;
  if (*piVar6 == 0) {
    iVar5 = FUN_8001f4c8(param_1,1);
    *piVar6 = iVar5;
  }
  if (*piVar6 != 0) {
    FUN_8001db2c(*piVar6,8);
    dVar7 = (double)FLOAT_803e7270;
    FUN_8001dd88(dVar7,dVar7,dVar7,*piVar6);
    FUN_8001dc90((double)fVar2,(double)fVar3,(double)fVar4,*piVar6);
    FUN_8001daf0(*piVar6,*(undefined *)(param_2 + 0x2d),*(undefined *)(param_2 + 0x2e),
                 *(undefined *)(param_2 + 0x2f),*(undefined *)(param_2 + 0x37));
    FUN_8001dc38((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1a)) -
                                DOUBLE_803e7278),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1c)) -
                                DOUBLE_803e7278),*piVar6);
    FUN_8001db24(*piVar6,*(undefined *)(param_2 + 0x39));
    FUN_8001db6c((double)FLOAT_803e7270,*piVar6,*(undefined *)(param_2 + 0x3a));
    if (piVar6[1] == 0) {
      if (*(short *)(param_2 + 0x24) == 0) {
        iVar5 = FUN_80054d54(0x5dc);
        piVar6[1] = iVar5;
      }
      else {
        iVar5 = FUN_80054d54();
        piVar6[1] = iVar5;
      }
      FUN_8001d98c(*piVar6,piVar6[1]);
    }
    if (*(char *)(param_2 + 0x26) == '\0') {
      dVar7 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x28)) -
                              DOUBLE_803e7278) / FLOAT_803e7274);
      if (dVar7 < (double)FLOAT_803e7260) {
        dVar7 = (double)FLOAT_803e7260;
      }
      dVar8 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a)) -
                              DOUBLE_803e7278) / FLOAT_803e7274);
      if (dVar8 < (double)FLOAT_803e7260) {
        dVar8 = (double)FLOAT_803e7260;
      }
      bVar1 = *(byte *)(param_2 + 0x3f);
      if (bVar1 == 0) {
        dVar9 = (double)FLOAT_803e7260;
        dVar10 = dVar9;
      }
      else {
        dVar9 = (double)(float)((double)CONCAT44(0x43300000,bVar1 & 0xf ^ 0x80000000) -
                               DOUBLE_803e7268);
        dVar10 = (double)(float)((double)CONCAT44(0x43300000,bVar1 >> 4 ^ 0x80000000) -
                                DOUBLE_803e7268);
      }
      FUN_8001d8f0(dVar8,-dVar8,-dVar7,dVar7,dVar9,dVar10,*piVar6);
    }
    else {
      fVar2 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x28)) -
                     DOUBLE_803e7278) / FLOAT_803e7274;
      if (fVar2 < FLOAT_803e7260) {
        fVar2 = FLOAT_803e7260;
      }
      fVar3 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a)) -
                     DOUBLE_803e7278) / FLOAT_803e7274;
      if (fVar3 < FLOAT_803e7260) {
        fVar3 = FLOAT_803e7260;
      }
      FUN_8001d878((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x27)) -
                                  DOUBLE_803e7278),(double)(fVar2 / fVar3),*piVar6);
    }
    FUN_8001d80c(*piVar6,*(undefined *)(param_2 + 0x36),*(undefined *)(param_2 + 0x3e));
    FUN_8001d84c((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x3b)) -
                                DOUBLE_803e7278),*piVar6);
    FUN_8001d820((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3c)) -
                                DOUBLE_803e7278),*piVar6);
    FUN_8001d620(*piVar6,*(undefined *)(param_2 + 0x33),(int)*(short *)(param_2 + 0x1e));
    FUN_8001dab8(*piVar6,*(undefined *)(param_2 + 0x30),*(undefined *)(param_2 + 0x31),
                 *(undefined *)(param_2 + 0x32),*(undefined *)(param_2 + 0x38));
  }
  return;
}

