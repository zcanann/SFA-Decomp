// Function: FUN_8017750c
// Entry: 8017750c
// Size: 1632 bytes

/* WARNING: Removing unreachable block (ram,0x80177b44) */
/* WARNING: Removing unreachable block (ram,0x8017751c) */

void FUN_8017750c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short *psVar6;
  uint uVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  
  iVar10 = *(int *)(param_9 + 0x4c);
  psVar9 = *(short **)(param_9 + 0xb8);
  psVar6 = (short *)FUN_8002bac4();
  if (psVar6 != (short *)0x0) {
    *psVar9 = *psVar9 - (ushort)DAT_803dc070;
    if (*psVar9 < 0) {
      *psVar9 = 0;
    }
    if ((((*(char *)(iVar10 + 0x1f) != '\0') && (*(char *)((int)psVar9 + 0xd) == '\0')) &&
        (-1 < DAT_803ddb38)) && ((int)DAT_803ddb38 == (int)*(char *)(iVar10 + 0x19))) {
      param_12 = FUN_80057360();
      param_11 = 0;
      param_13 = *DAT_803dd72c;
      (**(code **)(param_13 + 0x1c))(psVar6 + 6,(int)*psVar6);
      *(undefined *)((int)psVar9 + 0xd) = 1;
    }
    cVar2 = *(char *)(iVar10 + 0x1d);
    if (cVar2 == '\x02') {
      dVar11 = (double)*(float *)(psVar9 + 4);
      if ((double)FLOAT_803e4274 != dVar11) {
        param_2 = (double)(*(float *)(psVar6 + 0xc) - *(float *)(param_9 + 0x18));
        param_3 = (double)(*(float *)(psVar6 + 0xe) - *(float *)(param_9 + 0x1c));
        fVar3 = *(float *)(psVar6 + 0x10) - *(float *)(param_9 + 0x20);
        dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                      (float)(param_2 * param_2 + (double)(float)(param_3 * param_3)
                                             )));
      }
      uVar7 = FUN_80020078((int)psVar9[1]);
      if (((uVar7 == 0) || (*(char *)(psVar9 + 6) != '\0')) ||
         ((*(char *)(iVar10 + 0x1c) == '\0' ||
          (((double)*(float *)(psVar9 + 4) < dVar11 ||
           (*(int *)(psVar6 + 0x18) != *(int *)(param_9 + 0x30))))))) {
        if ((*(char *)(psVar9 + 6) == '\x01') &&
           ((((uVar7 = FUN_80020078((int)psVar9[1]), uVar7 != 0 && (*psVar9 == 0)) &&
             (dVar11 <= (double)*(float *)(psVar9 + 4))) && (-1 < *(char *)(iVar10 + 0x1a))))) {
          uVar12 = FUN_800201ac((int)psVar9[1],0);
          FUN_80055464(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (int)*(char *)(iVar10 + 0x1a),'\0',param_11,param_12,param_13,param_14,
                       param_15,param_16);
        }
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar9[2],param_9,0xffffffff);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
    else if (cVar2 < '\x02') {
      if (cVar2 == '\0') {
        if ((-1 < DAT_803ddb38) || (uVar7 = FUN_80020078(0xd53), uVar7 != 0)) {
          param_2 = (double)(*(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc));
          param_3 = (double)(*(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10));
          fVar3 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
          dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                        (float)(param_2 * param_2 +
                                               (double)(float)(param_3 * param_3))));
          if ((*(char *)(psVar9 + 6) == '\0') &&
             (((*(char *)(iVar10 + 0x1c) != '\0' && (dVar11 < (double)*(float *)(psVar9 + 4))) &&
              (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))) {
            if (*(short *)(param_9 + 0x46) == 0x27e) {
              FUN_800201ac(0xd53,1);
              iVar8 = FUN_80057360();
              param_13 = *DAT_803dd72c;
              (**(code **)(param_13 + 0x1c))(psVar6 + 6,(int)*psVar6,0,iVar8);
            }
            param_11 = 0xffffffff;
            param_12 = *DAT_803dd6d4;
            (**(code **)(param_12 + 0x48))((int)psVar9[2],param_9);
            FUN_800201ac(0xd53,0);
            DAT_803dda60 = 2;
            *(undefined *)(psVar9 + 6) = 1;
          }
        }
        if ((-1 < *(char *)(iVar10 + 0x1a)) &&
           (dVar11 = (double)FUN_800217c8((float *)(param_9 + 0x18),(float *)(psVar6 + 0xc)),
           dVar11 < (double)*(float *)(psVar9 + 4))) {
          FUN_80055464(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (int)*(char *)(iVar10 + 0x1a),'\x01',param_11,param_12,param_13,param_14,
                       param_15,param_16);
        }
      }
      else if (-1 < cVar2) {
        fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc);
        fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10);
        fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
        dVar11 = FUN_80293900((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
        if (((-1 < DAT_803ddb38) && (*(char *)(iVar10 + 0x1c) != '\0')) &&
           ((dVar11 < (double)FLOAT_803e4270 &&
            (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))) {
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
          DAT_803dda60 = 2;
        }
        if ((((*psVar9 == 0) &&
             (dVar11 < (double)(float)((double)CONCAT44(0x43300000,
                                                        (int)*(char *)(iVar10 + 0x1e) ^ 0x80000000)
                                      - DOUBLE_803e4278))) &&
            (bVar1 = -1 < *(char *)(iVar10 + 0x1a), bVar1)) && (bVar1)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        }
      }
    }
    else if (cVar2 == '\x04') {
      dVar11 = (double)*(float *)(psVar9 + 4);
      if ((double)FLOAT_803e4274 != dVar11) {
        param_2 = (double)(*(float *)(psVar6 + 0xc) - *(float *)(param_9 + 0x18));
        param_3 = (double)(*(float *)(psVar6 + 0xe) - *(float *)(param_9 + 0x1c));
        fVar3 = *(float *)(psVar6 + 0x10) - *(float *)(param_9 + 0x20);
        dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                      (float)(param_2 * param_2 + (double)(float)(param_3 * param_3)
                                             )));
      }
      if (((-1 < DAT_803ddb38) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar11 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))))) {
        param_11 = 0xffffffff;
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))((int)psVar9[2],param_9);
        DAT_803dda60 = 2;
        *(undefined *)(psVar9 + 6) = 1;
      }
      uVar7 = FUN_80020078((int)psVar9[1]);
      if ((((uVar7 != 0) && (*psVar9 == 0)) && (dVar11 <= (double)*(float *)(psVar9 + 4))) &&
         (-1 < *(char *)(iVar10 + 0x1a))) {
        uVar12 = FUN_800201ac((int)psVar9[1],0);
        FUN_80055464(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)*(char *)(iVar10 + 0x1a),'\x01',param_11,param_12,param_13,param_14,
                     param_15,param_16);
      }
    }
    else if (cVar2 < '\x04') {
      fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc);
      fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10);
      fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
      dVar11 = FUN_80293900((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
      uVar7 = FUN_80020078((int)psVar9[1]);
      if (((uVar7 != 0) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar11 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))))) {
        FUN_800201ac((int)psVar9[1],0);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar9[2],param_9,0xffffffff);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
  }
  return;
}

