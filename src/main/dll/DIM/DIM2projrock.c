#include "ghidra_import.h"
#include "main/dll/DIM/DIM2projrock.h"

extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006a10();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80017af8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_AddContactObject();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80047fdc();
extern undefined4 FUN_80053b3c();
extern int FUN_800620e8();
extern int FUN_800632f4();
extern undefined4 FUN_80080f14();
extern undefined4 FUN_800e8630();
extern int FUN_800e8b98();
extern undefined4 FUN_800ea9b8();
extern undefined4 FUN_801d8308();
extern undefined4 FUN_801d8480();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern uint FUN_80294d00();
extern undefined4 FUN_80294da0();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb90;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e57c0;
extern f64 DOUBLE_803e57d8;
extern f64 DOUBLE_803e57f8;
extern f64 DOUBLE_803e5820;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5770;
extern f32 FLOAT_803e5774;
extern f32 FLOAT_803e5778;
extern f32 FLOAT_803e577c;
extern f32 FLOAT_803e5780;
extern f32 FLOAT_803e5784;
extern f32 FLOAT_803e5788;
extern f32 FLOAT_803e5790;
extern f32 FLOAT_803e5794;
extern f32 FLOAT_803e5798;
extern f32 FLOAT_803e579c;
extern f32 FLOAT_803e57a4;
extern f32 FLOAT_803e57a8;
extern f32 FLOAT_803e57ac;
extern f32 FLOAT_803e57b0;
extern f32 FLOAT_803e57b4;
extern f32 FLOAT_803e57b8;
extern f32 FLOAT_803e57bc;
extern f32 FLOAT_803e57cc;
extern f32 FLOAT_803e57d0;
extern f32 FLOAT_803e57d4;
extern f32 FLOAT_803e57e0;
extern f32 FLOAT_803e57e4;
extern f32 FLOAT_803e57e8;
extern f32 FLOAT_803e57ec;
extern f32 FLOAT_803e57f0;
extern f32 FLOAT_803e5804;
extern f32 FLOAT_803e5808;
extern f32 FLOAT_803e580c;
extern f32 FLOAT_803e5810;
extern f32 FLOAT_803e5814;
extern f32 FLOAT_803e5818;
extern f32 FLOAT_803e5828;
extern f32 FLOAT_803e5834;
extern f32 FLOAT_803e5838;
extern f32 FLOAT_803e583c;
extern undefined uRam803dcb93;

/*
 * --INFO--
 *
 * Function: FUN_801b8860
 * EN v1.0 Address: 0x801B8860
 * EN v1.0 Size: 1024b
 * EN v1.1 Address: 0x801B8980
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b8860(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined uVar8;
  int *piVar6;
  undefined2 *puVar7;
  int *piVar9;
  int iVar10;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar11;
  int iVar12;
  int iVar13;
  undefined8 extraout_f1;
  undefined8 uVar14;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  int local_28 [10];
  
  iVar3 = FUN_8028683c();
  puVar11 = *(undefined4 **)(iVar3 + 0xb8);
  iVar12 = *(int *)(iVar3 + 0x4c);
  uVar14 = extraout_f1;
  uVar4 = FUN_80017690((int)*(short *)(iVar12 + 0x22));
  if (uVar4 != 0) {
    if ((*(byte *)((int)puVar11 + 0x9a7) & 4) == 0) {
      *puVar11 = *(undefined4 *)(iVar3 + 0xc);
      puVar11[1] = *(undefined4 *)(iVar3 + 0x10);
      puVar11[2] = *(undefined4 *)(iVar3 + 0x14);
    }
    else if ((*(byte *)((int)puVar11 + 0x9a7) & 2) == 0) {
      local_28[1] = 0x15;
      param_2 = (double)*(float *)(iVar3 + 0x10);
      param_3 = (double)*(float *)(iVar3 + 0x14);
      iVar5 = (**(code **)(*DAT_803dd71c + 0x14))((double)*(float *)(iVar3 + 0xc),local_28 + 1,1,10)
      ;
      uVar14 = extraout_f1_00;
      if (iVar5 != -1) {
        iVar5 = (**(code **)(*DAT_803dd71c + 0x1c))();
        (**(code **)(*DAT_803dd71c + 0x74))();
        in_r8 = *DAT_803dd71c;
        uVar8 = (**(code **)(in_r8 + 0x78))
                          (iVar5,puVar11 + 3,puVar11 + 0xcb,puVar11 + 0x193,puVar11 + 0x25b);
        *(undefined *)((int)puVar11 + 0x9a6) = uVar8;
        *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | 2;
        *puVar11 = *(undefined4 *)(iVar5 + 8);
        puVar11[1] = *(undefined4 *)(iVar5 + 0xc);
        puVar11[2] = *(undefined4 *)(iVar5 + 0x10);
        uVar14 = extraout_f1_01;
      }
    }
    sVar2 = *(short *)((int)puVar11 + 0x99e) - (ushort)DAT_803dc070;
    *(short *)((int)puVar11 + 0x99e) = sVar2;
    if (sVar2 < 1) {
      uVar4 = *(byte *)((int)puVar11 + 0x9a7) & 1;
      *(undefined2 *)((int)puVar11 + 0x99e) = *(undefined2 *)(puVar11 + 0x268);
      *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) & 0xfe;
      piVar6 = ObjGroup_GetObjects(0x2f,local_28);
      iVar10 = 0;
      iVar5 = uVar4 * 2;
      bVar1 = (byte)uVar4;
      piVar9 = piVar6;
      iVar13 = local_28[0];
      if (0 < local_28[0]) {
        do {
          if (*(short *)((int)puVar11 + iVar5 + 0x9a2) == *(short *)(*piVar9 + 0x46)) {
            iVar3 = *(int *)(piVar6[iVar10] + 0x4c);
            *(undefined4 *)(iVar3 + 8) = *puVar11;
            *(undefined4 *)(iVar3 + 0xc) = puVar11[1];
            *(undefined4 *)(iVar3 + 0x10) = puVar11[2];
            *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar12 + 0x14);
            (**(code **)(**(int **)(piVar6[iVar10] + 0x68) + 4))(piVar6[iVar10],iVar3,1);
            ObjGroup_RemoveObject(piVar6[iVar10],0x2f);
            ObjGroup_GetObjects(0x2f,local_28);
            iVar3 = 0;
            if (0 < local_28[0]) {
              if ((8 < local_28[0]) && (uVar4 = local_28[0] - 1U >> 3, 0 < local_28[0] + -8)) {
                do {
                  iVar3 = iVar3 + 8;
                  uVar4 = uVar4 - 1;
                } while (uVar4 != 0);
              }
              iVar12 = local_28[0] - iVar3;
              if (iVar3 < local_28[0]) {
                do {
                  iVar12 = iVar12 + -1;
                } while (iVar12 != 0);
              }
            }
            *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | bVar1 ^ 1;
            goto LAB_801b8cb8;
          }
          piVar9 = piVar9 + 1;
          iVar10 = iVar10 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
      uVar4 = FUN_80017ae8();
      if ((uVar4 & 0xff) != 0) {
        puVar7 = FUN_80017aa4(0x24,*(undefined2 *)((int)puVar11 + iVar5 + 0x9a2));
        *(undefined4 *)(puVar7 + 4) = *puVar11;
        *(undefined4 *)(puVar7 + 6) = puVar11[1];
        *(undefined4 *)(puVar7 + 8) = puVar11[2];
        *(undefined *)(puVar7 + 2) = *(undefined *)(iVar12 + 4);
        *(undefined *)(puVar7 + 3) = *(undefined *)(iVar12 + 6);
        *(undefined *)((int)puVar7 + 5) = *(undefined *)(iVar12 + 5);
        *(undefined *)((int)puVar7 + 7) = *(undefined *)(iVar12 + 7);
        *(undefined *)((int)puVar7 + 7) = 0xff;
        *(undefined *)((int)puVar7 + 3) = *(undefined *)(iVar12 + 3);
        *(undefined *)(puVar7 + 0xc) = *(undefined *)(iVar12 + 0x1c);
        puVar7[0xd] = (ushort)*(byte *)(iVar12 + 0x1a);
        puVar7[0xe] = (ushort)*(byte *)(iVar12 + 0x1b);
        *(undefined4 *)(puVar7 + 10) = *(undefined4 *)(iVar12 + 0x14);
        FUN_80017ae4(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7,5,
                     *(undefined *)(iVar3 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | bVar1 ^ 1;
      }
    }
  }
LAB_801b8cb8:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b8c60
 * EN v1.0 Address: 0x801B8C60
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B8D60
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b8c60(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b8c88
 * EN v1.0 Address: 0x801B8C88
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801B8D90
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b8c88(uint param_1)
{
  float fVar1;
  int iVar2;
  int local_18 [5];
  
  iVar2 = ObjHits_GetPriorityHit(param_1,local_18,(int *)0x0,(uint *)0x0);
  if (iVar2 == 0xe) {
    iVar2 = FUN_80017a98();
    FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    fVar1 = FLOAT_803e5774;
    *(float *)(param_1 + 0x24) = *(float *)(local_18[0] + 0x24) * FLOAT_803e5774;
    *(float *)(param_1 + 0x2c) = *(float *)(local_18[0] + 0x2c) * fVar1;
    FUN_80006824(param_1,0x1f9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b8d0c
 * EN v1.0 Address: 0x801B8D0C
 * EN v1.0 Size: 1568b
 * EN v1.1 Address: 0x801B8E14
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b8d0c(int *param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined4 *local_90;
  int aiStack_8c [7];
  float local_70;
  float local_6c;
  float local_68;
  
  fVar2 = FLOAT_803e577c;
  fVar1 = FLOAT_803e5778;
  pfVar6 = (float *)param_1[0x2e];
  if (*(char *)(pfVar6 + 1) == '\0') {
    param_1[9] = (int)((float)param_1[9] * FLOAT_803e577c);
    param_1[0xb] = (int)((float)param_1[0xb] * fVar2);
  }
  else {
    param_1[9] = (int)((float)param_1[9] * FLOAT_803e5778);
    param_1[0xb] = (int)((float)param_1[0xb] * fVar1);
  }
  fVar1 = FLOAT_803e5788;
  if (((((float)param_1[9] < FLOAT_803e5780) && (FLOAT_803e5784 < (float)param_1[9])) &&
      ((float)param_1[0xb] < FLOAT_803e5780)) && (FLOAT_803e5784 < (float)param_1[0xb])) {
    param_1[9] = (int)FLOAT_803e5788;
    param_1[0xb] = (int)fVar1;
  }
  FUN_80017a88((double)((float)param_1[9] * FLOAT_803dc074),(double)FLOAT_803e5788,
               (double)((float)param_1[0xb] * FLOAT_803dc074),(int)param_1);
  iVar3 = FUN_800620e8(param_1 + 0x20,param_1 + 3,(float *)0x1,aiStack_8c,param_1,8,0xffffffff,0xff,
                       0);
  if (iVar3 != 0) {
    dVar11 = -(double)(float)param_1[9];
    dVar10 = -(double)(float)param_1[10];
    dVar9 = -(double)(float)param_1[0xb];
    dVar8 = FUN_80293900((double)(float)(dVar9 * dVar9 +
                                        (double)(float)(dVar11 * dVar11 +
                                                       (double)(float)(dVar10 * dVar10))));
    if ((double)FLOAT_803e5788 != dVar8) {
      dVar7 = (double)(float)((double)FLOAT_803e5770 / dVar8);
      dVar11 = (double)(float)(dVar11 * dVar7);
      dVar10 = (double)(float)(dVar10 * dVar7);
      dVar9 = (double)(float)(dVar9 * dVar7);
    }
    dVar7 = (double)(FLOAT_803e5790 *
                    (float)(dVar9 * (double)local_68 +
                           (double)(float)(dVar11 * (double)local_70 +
                                          (double)(float)(dVar10 * (double)local_6c))));
    param_1[9] = (int)(float)((double)local_70 * dVar7);
    param_1[10] = (int)(float)((double)local_6c * dVar7);
    param_1[0xb] = (int)(float)((double)local_68 * dVar7);
    param_1[9] = (int)(float)((double)(float)param_1[9] - dVar11);
    param_1[10] = (int)(float)((double)(float)param_1[10] - dVar10);
    param_1[0xb] = (int)(float)((double)(float)param_1[0xb] - dVar9);
    dVar9 = (double)FLOAT_803e5794;
    param_1[9] = (int)((float)param_1[9] * (float)(dVar9 * dVar8));
    param_1[10] = (int)((float)param_1[10] * (float)((double)FLOAT_803e5774 * dVar8));
    param_1[0xb] = (int)((float)param_1[0xb] * (float)(dVar9 * dVar8));
  }
  param_1[4] = (int)-(FLOAT_803e5798 * FLOAT_803dc074 - (float)param_1[4]);
  iVar3 = FUN_800632f4((double)(float)param_1[3],(double)(float)param_1[4],(double)(float)param_1[5]
                       ,param_1,&local_90,0,0x11);
  *(undefined *)(pfVar6 + 1) = 0;
  iVar5 = 0;
  puVar4 = local_90;
  if (0 < iVar3) {
    do {
      if ((float)param_1[4] < FLOAT_803e579c + *(float *)*puVar4) {
        param_1[4] = *(int *)local_90[iVar5];
        ObjHits_AddContactObject(*(int *)(local_90[iVar5] + 0x10),(int)param_1);
        *(undefined *)(pfVar6 + 1) = 1;
        break;
      }
      puVar4 = puVar4 + 1;
      iVar5 = iVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if ((float)param_1[4] < *pfVar6) {
    param_1[4] = (int)*pfVar6;
  }
  FUN_800e8630((int)param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b932c
 * EN v1.0 Address: 0x801B932C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B9138
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b932c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9354
 * EN v1.0 Address: 0x801B9354
 * EN v1.0 Size: 824b
 * EN v1.1 Address: 0x801B916C
 * EN v1.1 Size: 832b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9354(uint param_1)
{
  byte bVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  
  pfVar8 = *(float **)(param_1 + 0xb8);
  iVar4 = FUN_80017a98();
  iVar7 = *(int *)(param_1 + 0x4c);
  bVar2 = false;
  iVar6 = 0;
  iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
  if (0 < iVar3) {
    do {
      if (*(int *)(*(int *)(param_1 + 0x58) + iVar6 + 0x100) == iVar4) {
        bVar2 = true;
        break;
      }
      iVar6 = iVar6 + 4;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  bVar1 = *(byte *)(pfVar8 + 1);
  if (bVar1 == 3) {
    *pfVar8 = *pfVar8 + FLOAT_803e57a8 * FLOAT_803dc074 +
                        FLOAT_803e57ac *
                        (float)((double)CONCAT44(0x43300000,
                                                 ((uint)(byte)((*pfVar8 < FLOAT_803e57a4) << 3) <<
                                                 0x1c) >> 0x1f ^ 0x80000000) - DOUBLE_803e57c0);
    if (FLOAT_803e57b0 < *pfVar8) {
      *pfVar8 = FLOAT_803e57b0;
    }
    *(float *)(param_1 + 0x10) = *pfVar8 * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
    if (*(float *)(iVar7 + 0xc) < *(float *)(param_1 + 0x10)) {
      FUN_80006824(param_1,0x1f8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined *)(pfVar8 + 1) = 1;
      if (bVar2) {
        *(undefined *)((int)pfVar8 + 5) = 1;
        *(undefined *)((int)pfVar8 + 6) = 0;
      }
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      FUN_8000680c(param_1,8);
      if (bVar2) {
        if ((*(char *)((int)pfVar8 + 6) != '\0') && (*(char *)((int)pfVar8 + 5) != '\0')) {
          FUN_80006824(param_1,0x113);
          *(undefined *)(pfVar8 + 1) = 4;
          *pfVar8 = FLOAT_803e57a4;
        }
      }
      else {
        *(undefined *)((int)pfVar8 + 6) = 1;
      }
      uVar5 = FUN_80017690((int)*(short *)(iVar7 + 0x20));
      if (uVar5 != 0) {
        FUN_80006824(param_1,0x113);
        *(undefined *)(pfVar8 + 1) = 4;
        *pfVar8 = FLOAT_803e57a4;
      }
    }
    else if (bVar1 != 0) {
      FUN_8000680c(param_1,8);
      if (*(char *)((int)pfVar8 + 5) == '\0') {
        uVar5 = FUN_80017690((int)*(short *)(iVar7 + 0x20));
        if (uVar5 == 0) {
          FUN_80006824(param_1,0x113);
          *(undefined *)(pfVar8 + 1) = 3;
          *pfVar8 = FLOAT_803e57a4;
          *(undefined *)((int)pfVar8 + 5) = 0;
          FUN_80017698((int)*(short *)(iVar7 + 0x1e),0);
        }
      }
      else if (!bVar2) {
        FUN_80006824(param_1,0x113);
        *(undefined *)(pfVar8 + 1) = 3;
        *pfVar8 = FLOAT_803e57a4;
        *(undefined *)((int)pfVar8 + 5) = 0;
        FUN_80017698((int)*(short *)(iVar7 + 0x1e),0);
      }
    }
  }
  else if (bVar1 < 5) {
    *pfVar8 = FLOAT_803e57b4 * FLOAT_803dc074 + *pfVar8;
    if (*pfVar8 < FLOAT_803e57b8) {
      *pfVar8 = FLOAT_803e57b8;
    }
    *(float *)(param_1 + 0x10) = *pfVar8 * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
    if (*(float *)(param_1 + 0x10) < *(float *)(iVar7 + 0xc) - FLOAT_803e57bc) {
      FUN_80006824(param_1,0x1f8);
      *(float *)(param_1 + 0x10) = *(float *)(iVar7 + 0xc) - FLOAT_803e57bc;
      *(undefined *)(pfVar8 + 1) = 2;
      FUN_80017698((int)*(short *)(iVar7 + 0x1e),1);
    }
    if ((*(char *)((int)pfVar8 + 5) == '\0') &&
       (uVar5 = FUN_80017690((int)*(short *)(iVar7 + 0x20)), uVar5 == 0)) {
      *(undefined *)(pfVar8 + 1) = 3;
      FUN_80017698((int)*(short *)(iVar7 + 0x1e),0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b968c
 * EN v1.0 Address: 0x801B968C
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x801B94AC
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b968c(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x1e));
  if (uVar1 == 0) {
    *(undefined *)(iVar2 + 4) = 1;
  }
  else {
    *(undefined *)(iVar2 + 4) = 2;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9700
 * EN v1.0 Address: 0x801B9700
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B9544
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9700(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9728
 * EN v1.0 Address: 0x801B9728
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B9578
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9728(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b972c
 * EN v1.0 Address: 0x801B972C
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801B97B8
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b972c(undefined2 *param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar3 + 0xa0) = *(undefined4 *)(param_2 + 0x14);
  *(float *)(iVar3 + 0xa4) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
              DOUBLE_803e57f8) / FLOAT_803e57e0;
  uVar2 = FUN_80017760(0xffffffe2,0x1e);
  *(float *)(iVar3 + 0xa8) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  uVar2 = FUN_80017760(0,(int)*(char *)(*(int *)(param_1 + 0x28) + 0x55) - 1);
  *(char *)((int)param_1 + 0xad) = (char)uVar2;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar2 = FUN_80017760(0,0xffff);
  *param_1 = (short)uVar2;
  *(undefined *)(param_1 + 0x1b) = 0;
  sVar1 = param_1[0x23];
  if (sVar1 == 0x10d) {
    uVar2 = FUN_80017760(0,0x32);
    *(float *)(iVar3 + 0xac) =
         FLOAT_803e57ec + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8)
    ;
    *(float *)(iVar3 + 0xb0) = FLOAT_803e57e8;
  }
  else if ((sVar1 < 0x10d) && (sVar1 == 0x109)) {
    uVar2 = FUN_80017760(0,0x28);
    *(float *)(iVar3 + 0xac) =
         FLOAT_803e57e4 + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8)
    ;
    *(float *)(iVar3 + 0xb0) = FLOAT_803e57e8;
  }
  else {
    uVar2 = FUN_80017760(0,0x28);
    *(float *)(iVar3 + 0xac) =
         FLOAT_803e57f0 + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8)
    ;
    *(float *)(iVar3 + 0xb0) = FLOAT_803e57e8;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b98ec
 * EN v1.0 Address: 0x801B98EC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B99C4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b98ec(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9914
 * EN v1.0 Address: 0x801B9914
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x801B99F8
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9914(uint param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  float *pfVar7;
  int local_28 [7];
  
  iVar6 = *(int *)(param_1 + 0x4c);
  pfVar7 = *(float **)(param_1 + 0xb8);
  bVar1 = *(byte *)((int)pfVar7 + 6);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar6 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
        if (iVar6 != 0xe) {
          return;
        }
        uVar3 = FUN_80017760(800,0x4b0);
        *(short *)(pfVar7 + 1) = (short)uVar3;
        *(undefined *)((int)pfVar7 + 6) = 3;
        *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
        FUN_80006824(param_1,0xa4);
        return;
      }
      if (*(char *)((int)pfVar7 + 7) == '\0') {
        iVar4 = FUN_800632f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                             (double)*(float *)(param_1 + 0x14),param_1,local_28,0,0);
        *pfVar7 = FLOAT_803e5808;
        for (iVar2 = 0; iVar2 < iVar4; iVar2 = iVar2 + 1) {
          pfVar5 = *(float **)(local_28[0] + iVar2 * 4);
          if (*(char *)(pfVar5 + 5) == '\x0e') {
            *pfVar7 = *pfVar5;
            iVar2 = iVar4;
          }
        }
        if (FLOAT_803e5808 != *pfVar7) {
          *(undefined *)((int)pfVar7 + 7) = 1;
        }
      }
      if ((0 < *(short *)(pfVar7 + 2)) &&
         (*(ushort *)(pfVar7 + 2) = *(short *)(pfVar7 + 2) - (ushort)DAT_803dc070,
         *(short *)(pfVar7 + 2) < 1)) {
        FUN_80006824(param_1,0xa5);
      }
      *(float *)(param_1 + 0x28) = -(FLOAT_803e580c * FLOAT_803dc074 - *(float *)(param_1 + 0x28));
      if (*(float *)(param_1 + 0x28) < FLOAT_803e5810) {
        *(float *)(param_1 + 0x28) = FLOAT_803e5810;
      }
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
      if (*pfVar7 <= *(float *)(param_1 + 0x10)) {
        return;
      }
      FUN_80017698((int)*(short *)(iVar6 + 0x1e),1);
      *(undefined *)((int)pfVar7 + 6) = 2;
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(param_1 + 0xc),(double)*pfVar7,
                 (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e5814,param_1);
      (**(code **)(*DAT_803dd718 + 0x14))
                ((double)*(float *)(param_1 + 0xc),(double)*pfVar7,
                 (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e5818,0,2);
      FUN_80006824(param_1,0xa6);
      *(undefined2 *)(pfVar7 + 2) = 0x96;
      return;
    }
    if (bVar1 < 4) {
      *(undefined2 *)(param_1 + 2) = *(undefined2 *)(pfVar7 + 1);
      *(short *)(pfVar7 + 1) =
           (short)(int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(pfVar7 + 1) ^ 0x80000000
                                                ) - DOUBLE_803e5820) * FLOAT_803e5804);
      if (9 < *(short *)(param_1 + 2)) {
        return;
      }
      *(undefined2 *)(param_1 + 2) = 0;
      *(undefined *)((int)pfVar7 + 6) = 1;
      *(undefined2 *)(pfVar7 + 2) = 0x3c;
      return;
    }
  }
  if ((0 < *(short *)(pfVar7 + 2)) &&
     (*(ushort *)(pfVar7 + 2) = *(short *)(pfVar7 + 2) - (ushort)DAT_803dc070,
     *(short *)(pfVar7 + 2) < 1)) {
    FUN_80006824(param_1,0x155);
  }
  iVar2 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -8;
  if (iVar2 < 0) {
    iVar2 = 0;
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(float *)(param_1 + 0x28) = FLOAT_803e5818;
  }
  *(char *)(param_1 + 0x36) = (char)iVar2;
  *(float *)(param_1 + 0x10) =
       *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9c2c
 * EN v1.0 Address: 0x801B9C2C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801B9D1C
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9c2c(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x1e));
  if (uVar1 == 0) {
    *(undefined *)(iVar2 + 6) = 0;
    *(undefined *)(param_1 + 0x1b) = 0xff;
  }
  else {
    *(undefined *)(iVar2 + 6) = 2;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(float *)(param_1 + 0x14) = FLOAT_803e5818;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9cc4
 * EN v1.0 Address: 0x801B9CC4
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801B9DC4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9cc4(int param_1)
{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = *(char **)(param_1 + 0xb8);
  if ((pcVar1[2] & 1U) == 0) {
    iVar2 = *(int *)(param_1 + 0x4c);
    if (('\0' < *pcVar1) && (*pcVar1 = *pcVar1 + -1, *pcVar1 == '\0')) {
      pcVar1[2] = pcVar1[2] | 1;
      FUN_80017698((int)*(short *)(iVar2 + 0x1e),1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9d2c
 * EN v1.0 Address: 0x801B9D2C
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801B9E48
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9d2c(void)
{
  FUN_80047fdc((double)FLOAT_803e5828,0xc0);
  FUN_800067c0((int *)0xc4,0);
  FUN_80053b3c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9d64
 * EN v1.0 Address: 0x801B9D64
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B9E80
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9d64(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b9d8c
 * EN v1.0 Address: 0x801B9D8C
 * EN v1.0 Size: 1276b
 * EN v1.1 Address: 0x801B9EB0
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b9d8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char *pcVar4;
  undefined8 uVar5;
  undefined4 auStack_18 [5];
  
  if (*(int *)(param_9 + 0xf4) != 0) {
    if (*(int *)(param_9 + 0xf4) == 2) {
      uVar5 = FUN_80006724(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x163
                           ,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x166,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x165,0
                           ,in_r7,in_r8,in_r9,in_r10);
      FUN_80006724(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x164,0,in_r7,
                   in_r8,in_r9,in_r10);
    }
    else {
      uVar5 = FUN_80006728(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x163
                           ,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x166,0
                           ,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x165,0
                           ,in_r7,in_r8,in_r9,in_r10);
      FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x164,0,in_r7,
                   in_r8,in_r9,in_r10);
    }
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  pcVar4 = *(char **)(param_9 + 0xb8);
  if (((pcVar4[4] != '\x01') && (pcVar4[4] == '\0')) && (uVar3 = FUN_80017690(0xacd), uVar3 != 0)) {
    FUN_80017698(0xcc3,1);
    pcVar4[4] = '\x01';
  }
  bVar1 = pcVar4[3];
  if ((uint)bVar1 != (uint)(byte)(&DAT_803dcb90)[*pcVar4]) {
    if ((int)((uint)bVar1 - (uint)(byte)(&DAT_803dcb90)[*pcVar4]) < 1) {
      pcVar4[3] = bVar1 + 1;
    }
    else {
      pcVar4[3] = bVar1 - 1;
    }
    FUN_80047fdc((double)FLOAT_803e5828,pcVar4[3]);
  }
  iVar2 = FUN_80017a98();
  uVar3 = FUN_80294d00(iVar2,auStack_18);
  if (uVar3 == 0) {
    if (((*(uint *)(pcVar4 + 8) & 2) != 0) && (*(int **)(pcVar4 + 0xc) != (int *)0xd7)) {
      FUN_800067c0(*(int **)(pcVar4 + 0xc),0);
      pcVar4[0xc] = '\0';
      pcVar4[0xd] = '\0';
      pcVar4[0xe] = '\0';
      pcVar4[0xf] = -0x29;
      FUN_800067c0((int *)0xd7,1);
    }
  }
  else if (((*(uint *)(pcVar4 + 8) & 2) != 0) && (*(int **)(pcVar4 + 0xc) != (int *)0xe0)) {
    FUN_800067c0(*(int **)(pcVar4 + 0xc),0);
    pcVar4[0xc] = '\0';
    pcVar4[0xd] = '\0';
    pcVar4[0xe] = '\0';
    pcVar4[0xf] = -0x20;
    FUN_800067c0((int *)0xe0,1);
  }
  FUN_801d8308(pcVar4 + 8,1,-1,-1,0xd99,(int *)0xde);
  FUN_801d8308(pcVar4 + 8,2,-1,-1,0xda5,*(int **)(pcVar4 + 0xc));
  FUN_801d8308(pcVar4 + 8,8,-1,-1,0xf04,(int *)0x96);
  FUN_801d8480(pcVar4 + 8,0x10,-1,-1,0xf04,(int *)0x2c);
  FUN_801d8308(pcVar4 + 8,4,-1,-1,0xcbb,(int *)0xc4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ba288
 * EN v1.0 Address: 0x801BA288
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x801BA134
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ba288(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  uint uVar2;
  byte bVar4;
  undefined *puVar3;
  undefined8 uVar5;
  
  iVar1 = FUN_800e8b98();
  if (iVar1 == 0) {
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_9 + 0xf4) = 2;
  }
  for (bVar4 = 1; bVar4 < 0x2e; bVar4 = bVar4 + 1) {
    FUN_800ea9b8();
  }
  puVar3 = *(undefined **)(param_9 + 0xb8);
  *puVar3 = (char)*(undefined2 *)(param_10 + 0x1a);
  puVar3[1] = *puVar3;
  uVar2 = FUN_80017690((int)*(short *)(param_10 + 0x1e));
  puVar3[2] = puVar3[2] | uVar2 != 0;
  *(undefined4 *)(puVar3 + 0xc) = 0xd7;
  puVar3[4] = 0;
  if ((puVar3[2] & 1) == 0) {
    *puVar3 = 3;
    puVar3[3] = uRam803dcb93;
    uVar5 = FUN_80047fdc((double)FLOAT_803e5828,uRam803dcb93);
  }
  else {
    *puVar3 = 0;
    puVar3[3] = DAT_803dcb90;
    uVar5 = FUN_80047fdc((double)FLOAT_803e5828,DAT_803dcb90);
  }
  FUN_800067c0((int *)0xdd,1);
  FUN_80080f14(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ba434
 * EN v1.0 Address: 0x801BA434
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801BA27C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ba434(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ba45c
 * EN v1.0 Address: 0x801BA45C
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x801BA2B0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ba45c(int param_1)
{
  float fVar1;
  undefined uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_80039520(param_1,0);
  if (iVar3 != 0) {
    if (*(short *)(param_1 + 0x46) == 0xd1) {
      uVar2 = (undefined)(int)FLOAT_803e5834;
      *(undefined *)(iVar3 + 0xc) = uVar2;
      *(undefined *)(iVar3 + 0xd) = uVar2;
      *(undefined *)(iVar3 + 0xe) = uVar2;
    }
    else {
      uVar2 = (undefined)(int)FLOAT_803e5834;
      *(undefined *)(iVar3 + 0xc) = uVar2;
      *(undefined *)(iVar3 + 0xd) = uVar2;
      *(undefined *)(iVar3 + 0xe) = uVar2;
    }
  }
  iVar3 = FUN_80017a98();
  dVar5 = FUN_80017714((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18));
  if (dVar5 < (double)FLOAT_803e5838) {
    fVar1 = *(float *)(iVar4 + 0x24) - FLOAT_803dc074;
    *(float *)(iVar4 + 0x24) = fVar1;
    if (fVar1 < FLOAT_803e5834) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x20d,0,2,0xffffffff,0);
      *(float *)(iVar4 + 0x24) = FLOAT_803e583c;
    }
  }
  return;
}
