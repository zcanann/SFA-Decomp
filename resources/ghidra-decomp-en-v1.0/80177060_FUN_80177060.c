// Function: FUN_80177060
// Entry: 80177060
// Size: 1632 bytes

/* WARNING: Removing unreachable block (ram,0x80177698) */

void FUN_80177060(int param_1)

{
  bool bVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short *psVar6;
  undefined4 uVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar10 = *(int *)(param_1 + 0x4c);
  psVar9 = *(short **)(param_1 + 0xb8);
  psVar6 = (short *)FUN_8002b9ec();
  if (psVar6 != (short *)0x0) {
    *psVar9 = *psVar9 - (ushort)DAT_803db410;
    if (*psVar9 < 0) {
      *psVar9 = 0;
    }
    if ((((*(char *)(iVar10 + 0x1f) != '\0') && (*(char *)((int)psVar9 + 0xd) == '\0')) &&
        (-1 < DAT_803dceb8)) && ((int)DAT_803dceb8 == (int)*(char *)(iVar10 + 0x19))) {
      uVar7 = FUN_800571e4();
      (**(code **)(*DAT_803dcaac + 0x1c))(psVar6 + 6,(int)*psVar6,0,uVar7);
      *(undefined *)((int)psVar9 + 0xd) = 1;
    }
    cVar2 = *(char *)(iVar10 + 0x1d);
    if (cVar2 == '\x02') {
      dVar12 = (double)*(float *)(psVar9 + 4);
      if ((double)FLOAT_803e35dc != dVar12) {
        fVar3 = *(float *)(psVar6 + 0xc) - *(float *)(param_1 + 0x18);
        fVar4 = *(float *)(psVar6 + 0xe) - *(float *)(param_1 + 0x1c);
        fVar5 = *(float *)(psVar6 + 0x10) - *(float *)(param_1 + 0x20);
        dVar12 = (double)FUN_802931a0((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
      }
      iVar8 = FUN_8001ffb4((int)psVar9[1]);
      if (((iVar8 == 0) || (*(char *)(psVar9 + 6) != '\0')) ||
         ((*(char *)(iVar10 + 0x1c) == '\0' ||
          (((double)*(float *)(psVar9 + 4) < dVar12 ||
           (*(int *)(psVar6 + 0x18) != *(int *)(param_1 + 0x30))))))) {
        if ((*(char *)(psVar9 + 6) == '\x01') &&
           ((((iVar8 = FUN_8001ffb4((int)psVar9[1]), iVar8 != 0 && (*psVar9 == 0)) &&
             (dVar12 <= (double)*(float *)(psVar9 + 4))) && (-1 < *(char *)(iVar10 + 0x1a))))) {
          FUN_800200e8((int)psVar9[1],0);
          FUN_800552e8((int)*(char *)(iVar10 + 0x1a),0);
        }
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))((int)psVar9[2],param_1,0xffffffff);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
    else if (cVar2 < '\x02') {
      if (cVar2 == '\0') {
        if ((((-1 < DAT_803dceb8) || (iVar8 = FUN_8001ffb4(0xd53), iVar8 != 0)) &&
            (fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_1 + 0xc),
            fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_1 + 0x10),
            fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_1 + 0x14),
            dVar12 = (double)FUN_802931a0((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4)),
            *(char *)(psVar9 + 6) == '\0')) &&
           (((*(char *)(iVar10 + 0x1c) != '\0' && (dVar12 < (double)*(float *)(psVar9 + 4))) &&
            (*(int *)(psVar6 + 0x18) == *(int *)(param_1 + 0x30))))) {
          if (*(short *)(param_1 + 0x46) == 0x27e) {
            FUN_800200e8(0xd53,1);
            uVar7 = FUN_800571e4();
            (**(code **)(*DAT_803dcaac + 0x1c))(psVar6 + 6,(int)*psVar6,0,uVar7);
          }
          (**(code **)(*DAT_803dca54 + 0x48))((int)psVar9[2],param_1,0xffffffff);
          FUN_800200e8(0xd53,0);
          DAT_803dcde0 = 2;
          *(undefined *)(psVar9 + 6) = 1;
        }
        if ((-1 < *(char *)(iVar10 + 0x1a)) &&
           (dVar12 = (double)FUN_80021704(param_1 + 0x18,psVar6 + 0xc),
           dVar12 < (double)*(float *)(psVar9 + 4))) {
          FUN_800552e8((int)*(char *)(iVar10 + 0x1a),1);
        }
      }
      else if (-1 < cVar2) {
        fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_1 + 0xc);
        fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_1 + 0x10);
        fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_1 + 0x14);
        dVar12 = (double)FUN_802931a0((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
        if ((((-1 < DAT_803dceb8) && (*(char *)(iVar10 + 0x1c) != '\0')) &&
            (dVar12 < (double)FLOAT_803e35d8)) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_1 + 0x30))) {
          (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
          DAT_803dcde0 = 2;
        }
        if (((*psVar9 == 0) &&
            (dVar12 < (double)(float)((double)CONCAT44(0x43300000,
                                                       (int)*(char *)(iVar10 + 0x1e) ^ 0x80000000) -
                                     DOUBLE_803e35e0))) &&
           ((bVar1 = -1 < *(char *)(iVar10 + 0x1a), bVar1 && (bVar1)))) {
          (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        }
      }
    }
    else if (cVar2 == '\x04') {
      dVar12 = (double)*(float *)(psVar9 + 4);
      if ((double)FLOAT_803e35dc != dVar12) {
        fVar3 = *(float *)(psVar6 + 0xc) - *(float *)(param_1 + 0x18);
        fVar4 = *(float *)(psVar6 + 0xe) - *(float *)(param_1 + 0x1c);
        fVar5 = *(float *)(psVar6 + 0x10) - *(float *)(param_1 + 0x20);
        dVar12 = (double)FUN_802931a0((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
      }
      if (((-1 < DAT_803dceb8) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar12 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_1 + 0x30))))))) {
        (**(code **)(*DAT_803dca54 + 0x48))((int)psVar9[2],param_1,0xffffffff);
        DAT_803dcde0 = 2;
        *(undefined *)(psVar9 + 6) = 1;
      }
      iVar8 = FUN_8001ffb4((int)psVar9[1]);
      if ((((iVar8 != 0) && (*psVar9 == 0)) && (dVar12 <= (double)*(float *)(psVar9 + 4))) &&
         (-1 < *(char *)(iVar10 + 0x1a))) {
        FUN_800200e8((int)psVar9[1],0);
        FUN_800552e8((int)*(char *)(iVar10 + 0x1a),1);
      }
    }
    else if (cVar2 < '\x04') {
      fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_1 + 0xc);
      fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_1 + 0x10);
      fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_1 + 0x14);
      dVar12 = (double)FUN_802931a0((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
      iVar8 = FUN_8001ffb4((int)psVar9[1]);
      if (((iVar8 != 0) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar12 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_1 + 0x30))))))) {
        FUN_800200e8((int)psVar9[1],0);
        (**(code **)(*DAT_803dca54 + 0x48))((int)psVar9[2],param_1,0xffffffff);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return;
}

