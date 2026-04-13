// Function: FUN_801bfc68
// Entry: 801bfc68
// Size: 540 bytes

void FUN_801bfc68(int param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  int iVar9;
  int iVar10;
  float *pfVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  int local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  iVar10 = *(int *)(param_1 + 0xb8);
  uVar8 = 0x16;
  if (param_3 != 0) {
    uVar8 = 0x17;
  }
  uVar6 = 0;
  uVar7 = 0x102;
  iVar9 = *DAT_803dd738;
  (**(code **)(iVar9 + 0x58))((double)FLOAT_803e5978,param_1,param_2,iVar10,0);
  *(undefined4 *)(param_1 + 0xbc) = 0;
  fVar1 = FLOAT_803e5970;
  pfVar11 = *(float **)(iVar10 + 0x40c);
  *pfVar11 = FLOAT_803e5970;
  pfVar11[1] = fVar1;
  uVar2 = FUN_80022264(0xffff8001,0x7fff);
  *(short *)(pfVar11 + 5) = (short)uVar2;
  fVar1 = FLOAT_803e5970;
  pfVar11[2] = FLOAT_803e5970;
  *(undefined2 *)((int)pfVar11 + 0x16) = 0;
  pfVar11[4] = fVar1;
  dVar12 = (double)*(float *)(param_1 + 0x10);
  dVar13 = (double)*(float *)(param_1 + 0x14);
  uVar5 = 0;
  iVar10 = FUN_80065fcc((double)*(float *)(param_1 + 0xc),dVar12,dVar13,param_1,local_18,0,0);
  pfVar11[3] = FLOAT_803e5970;
  if (iVar10 != 0) {
    pfVar11[3] = FLOAT_803e59bc;
    iVar4 = 0;
    if (0 < iVar10) {
      do {
        fVar1 = **(float **)(local_18[0] + iVar4) - *(float *)(param_1 + 0x10);
        if ((*(char *)(*(float **)(local_18[0] + iVar4) + 5) == '\x0e') && (pfVar11[3] < fVar1)) {
          pfVar11[3] = fVar1;
        }
        iVar4 = iVar4 + 4;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
    }
  }
  pfVar11[3] = pfVar11[3] + *(float *)(param_1 + 0x10);
  uStack_c = FUN_80022264(0,99);
  uStack_c = uStack_c ^ 0x80000000;
  local_10 = 0x43300000;
  FUN_8003042c((double)((float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e5990) /
                       FLOAT_803e59c0),dVar12,dVar13,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0,0,uVar5
               ,uVar6,uVar7,uVar8,iVar9);
  FUN_8002fb40((double)FLOAT_803e59b8,(double)FLOAT_803dc074);
  piVar3 = FUN_8001f58c(param_1,'\x01');
  pfVar11[6] = (float)piVar3;
  if (pfVar11[6] != 0.0) {
    FUN_8001dbf0((int)pfVar11[6],2);
    FUN_8001dbb4((int)pfVar11[6],0,0xff,0,0);
    FUN_8001dbd8((int)pfVar11[6],1);
    dVar12 = (double)FLOAT_803e5978;
    FUN_8001dcfc((double)FLOAT_803e59c4,dVar12,(int)pfVar11[6]);
    FUN_8001d7f4((double)FLOAT_803e59c8,dVar12,dVar13,in_f4,in_f5,in_f6,in_f7,in_f8,pfVar11[6],0,0,
                 0xff,0,0x7f,uVar8,iVar9);
    FUN_8001d7d8((double)FLOAT_803e599c,(int)pfVar11[6]);
  }
  return;
}

