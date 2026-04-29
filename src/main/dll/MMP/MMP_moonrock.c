#include "ghidra_import.h"
#include "main/dll/MMP/MMP_moonrock.h"

extern undefined4 FUN_80006810();
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern uint FUN_80017690();
extern uint FUN_80017760();
extern undefined4 FUN_80017814();
extern int FUN_80017a98();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_80048000();
extern undefined4 FUN_8004800c();
extern int FUN_8007f7c0();
extern undefined4 FUN_80081028();
extern uint FUN_80081030();
extern undefined4 FUN_800810ec();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_801993b0();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e4d18;
extern f64 DOUBLE_803e4d30;
extern f64 DOUBLE_803e4d40;
extern f64 DOUBLE_803e4d48;
extern f64 DOUBLE_803e4d58;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4d00;
extern f32 FLOAT_803e4d04;
extern f32 FLOAT_803e4d08;
extern f32 FLOAT_803e4d0c;
extern f32 FLOAT_803e4d10;
extern f32 FLOAT_803e4d14;
extern f32 FLOAT_803e4d20;
extern f32 FLOAT_803e4d24;
extern f32 FLOAT_803e4d28;
extern f32 FLOAT_803e4d38;
extern f32 FLOAT_803e4d50;
extern f32 FLOAT_803e4d54;

/*
 * --INFO--
 *
 * Function: FUN_801978a8
 * EN v1.0 Address: 0x801978A8
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801978DC
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801978a8(int param_1,int param_2)
{
  uint uVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  *piVar2 = (int)*(char *)(param_2 + 0x19);
  piVar2[2] = (int)*(short *)(param_2 + 0x1a) << 8;
  *(char *)(piVar2 + 1) = (char)*(undefined2 *)(param_2 + 0x1c);
  piVar2[3] = (int)*(char *)(param_2 + 0x18) << 8;
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x1e));
  *(byte *)(piVar2 + 5) = (byte)((uVar1 & 1) << 6) | *(byte *)(piVar2 + 5) & 0xbf;
  if ((uVar1 & 1) != 0) {
    piVar2[4] = piVar2[2];
    *(byte *)(piVar2 + 5) = *(byte *)(piVar2 + 5) & 0xdf | 0x20;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80197960
 * EN v1.0 Address: 0x80197960
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801979B8
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80197960(int param_1)
{
  if (*(char *)(*(int *)(param_1 + 0xb8) + 4) < '\0') {
    FUN_80048000();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80197990
 * EN v1.0 Address: 0x80197990
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x801979F0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80197990(int param_1)
{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pfVar4 = *(float **)(param_1 + 0xb8);
  if ((int)*(short *)(iVar5 + 0x18) == 0xffffffff) {
    uVar2 = 1;
  }
  else {
    uVar2 = FUN_80017690((int)*(short *)(iVar5 + 0x18));
    uVar2 = uVar2 & 0xff;
  }
  if (((uVar2 == 0) || ((*(byte *)(pfVar4 + 1) >> 6 & 1) != 0)) &&
     ((uVar2 != 0 || (-1 < *(char *)(pfVar4 + 1))))) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if (bVar1) {
    if (uVar2 == 0) {
      if ((*(byte *)(iVar5 + 0x1a) & 4) == 0) {
        *pfVar4 = -(FLOAT_803e4d04 * FLOAT_803dc074 - *pfVar4);
      }
      else {
        *pfVar4 = -(FLOAT_803e4d00 * FLOAT_803dc074 - *pfVar4);
      }
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xbf;
    }
    else {
      if ((*(byte *)(iVar5 + 0x1a) & 2) == 0) {
        *pfVar4 = FLOAT_803e4d04 * FLOAT_803dc074 + *pfVar4;
      }
      else {
        *pfVar4 = FLOAT_803e4d00 * FLOAT_803dc074 + *pfVar4;
      }
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f | 0x80;
    }
    if (FLOAT_803e4d08 < *pfVar4) {
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f | 0x80;
      if (FLOAT_803e4d0c < *pfVar4) {
        *pfVar4 = FLOAT_803e4d0c;
        *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xbf | 0x40;
      }
      uVar3 = (int)*(short *)(iVar5 + 0x1c) ^ 0x80000000;
      uVar2 = (int)*(short *)(iVar5 + 0x20) ^ 0x80000000;
      dVar6 = (double)(*(float *)(param_1 + 0x10) +
                      *pfVar4 * ((float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4d18) -
                                (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18)) +
                      (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18));
      FUN_8004800c(dVar6,(double)((float)((double)(float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)(iVar5 + 
                                                  0x1e) ^ 0x80000000) - DOUBLE_803e4d18) + dVar6) -
                                 (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4d18)),
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar5 + 0x24) ^ 0x80000000) -
                                  DOUBLE_803e4d18),
                   (double)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar5 + 0x22) ^ 0x80000000) -
                                   DOUBLE_803e4d18) / FLOAT_803e4d10),(double)FLOAT_803e4d14,
                   *(byte *)(iVar5 + 0x1a) & 1);
    }
    else {
      *pfVar4 = FLOAT_803e4d08;
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0x7f;
      FUN_80048000();
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80197c38
 * EN v1.0 Address: 0x80197C38
 * EN v1.0 Size: 476b
 * EN v1.1 Address: 0x80197C78
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80197c38(int param_1,int param_2)
{
  uint uVar1;
  uint uVar2;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0x7f;
  *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0xbf;
  *pfVar3 = FLOAT_803e4d08;
  if ((*(byte *)(param_2 + 0x1a) & 8) != 0) {
    if ((int)*(short *)(param_2 + 0x18) == 0xffffffff) {
      uVar1 = 1;
    }
    else {
      uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x18));
      uVar1 = uVar1 & 0xff;
    }
    if (uVar1 != 0) {
      *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0xbf | 0x40;
      *(byte *)(pfVar3 + 1) = *(byte *)(pfVar3 + 1) & 0x7f | 0x80;
      *pfVar3 = FLOAT_803e4d0c;
      uVar2 = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
      uVar1 = (int)*(short *)(param_2 + 0x20) ^ 0x80000000;
      dVar4 = (double)(*(float *)(param_1 + 0x10) +
                      *pfVar3 * ((float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18) -
                                (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e4d18)) +
                      (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e4d18));
      FUN_8004800c(dVar4,(double)((float)((double)(float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)(param_2 +
                                                                                          0x1e) ^
                                                                           0x80000000) -
                                                         DOUBLE_803e4d18) + dVar4) -
                                 (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4d18)),
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(param_2 + 0x24) ^ 0x80000000) -
                                  DOUBLE_803e4d18),
                   (double)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_2 + 0x22) ^ 0x80000000) -
                                   DOUBLE_803e4d18) / FLOAT_803e4d10),(double)FLOAT_803e4d14,
                   *(byte *)(param_2 + 0x1a) & 1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80197e14
 * EN v1.0 Address: 0x80197E14
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80197E24
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80197e14(int param_1)
{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,0x48);
  if (*puVar1 != 0) {
    FUN_80017814(*puVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80197e54
 * EN v1.0 Address: 0x80197E54
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80197E64
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80197e54(int param_1)
{
  if ((float *)**(undefined4 **)(param_1 + 0xb8) != (float *)0x0) {
    FUN_80081028((float *)**(undefined4 **)(param_1 + 0xb8));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80197e84
 * EN v1.0 Address: 0x80197E84
 * EN v1.0 Size: 940b
 * EN v1.1 Address: 0x80197E94
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80197e84(void)
{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint *puVar7;
  int local_28 [2];
  undefined8 local_20;
  
  iVar1 = FUN_80286840();
  puVar7 = *(uint **)(iVar1 + 0xb8);
  iVar5 = *(int *)(iVar1 + 0x4c);
  uVar2 = (uint)*(short *)(iVar5 + 0x24);
  if (uVar2 != 0xffffffff) {
    if (*(char *)((int)puVar7 + 0x25) < '\0') {
      uVar2 = FUN_80017690(uVar2);
      if (uVar2 == 0) {
        *(byte *)((int)puVar7 + 0x25) = *(byte *)((int)puVar7 + 0x25) & 0x7f;
        if (*puVar7 != 0) {
          FUN_80017814(*puVar7);
          *puVar7 = 0;
        }
      }
    }
    else {
      uVar2 = FUN_80017690(uVar2);
      if (uVar2 != 0) {
        *(byte *)((int)puVar7 + 0x25) = *(byte *)((int)puVar7 + 0x25) & 0x7f | 0x80;
      }
    }
  }
  if ((*puVar7 == 0) && (*(char *)((int)puVar7 + 0x25) < '\0')) {
    puVar7[6] = (uint)((float)puVar7[6] - FLOAT_803dc074);
    if ((float)puVar7[6] <= FLOAT_803e4d20) {
      local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x23) * 0x3c ^ 0x80000000);
      puVar7[6] = (uint)((float)puVar7[6] + (float)(local_20 - DOUBLE_803e4d30));
      piVar3 = ObjGroup_GetObjects(0x48,local_28);
      iVar6 = 0;
      piVar4 = piVar3;
      iVar5 = local_28[0];
      if (0 < local_28[0]) {
        do {
          if (*(uint *)(*(int *)(*piVar4 + 0x4c) + 0x14) == puVar7[8]) break;
          piVar4 = piVar4 + 1;
          iVar6 = iVar6 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      if (iVar6 == local_28[0]) {
        *(byte *)((int)puVar7 + 0x25) = *(byte *)((int)puVar7 + 0x25) & 0x7f;
        goto LAB_801981b8;
      }
      uVar2 = FUN_80017760(0xfffffffb,5);
      uVar2 = FUN_80081030((double)(float)puVar7[2],(double)(float)puVar7[3],iVar1 + 0xc,
                           piVar3[iVar6] + 0xc,(ushort)*(byte *)(puVar7 + 7) + (short)uVar2,
                           *(undefined *)((int)puVar7 + 0x1d),
                           (*(byte *)((int)puVar7 + 0x25) >> 5 & 1) != 0);
      *puVar7 = uVar2;
      puVar7[1] = (uint)FLOAT_803e4d20;
      if ((*(byte *)(puVar7 + 9) & 1) != 0) {
        FUN_800810ec(iVar1,1,7,0x1e,0);
      }
      iVar5 = *(int *)(piVar3[iVar6] + 0xb8);
      if ((*(byte *)(iVar5 + 0x24) & 1) != 0) {
        FUN_800810ec(piVar3[iVar6],1,7,0x1e,0);
      }
      if ((*(byte *)(puVar7 + 9) & 2) != 0) {
        FUN_800810f4((double)(float)puVar7[5],(double)FLOAT_803e4d24,iVar1,5,1,1,100,0,0);
      }
      if ((*(byte *)(iVar5 + 0x24) & 2) != 0) {
        FUN_800810f4((double)*(float *)(iVar5 + 0x14),(double)FLOAT_803e4d24,piVar3[iVar6],5,1,1,100
                     ,0,0);
      }
    }
  }
  if (*puVar7 != 0) {
    if ((*(byte *)((int)puVar7 + 0x25) >> 6 & 1) == 0) {
      puVar7[1] = (uint)((float)puVar7[1] + FLOAT_803dc074);
      local_20 = (double)(longlong)(int)(FLOAT_803e4d28 + (float)puVar7[1]);
      *(short *)(*puVar7 + 0x20) = (short)(int)(FLOAT_803e4d28 + (float)puVar7[1]);
    }
    uVar2 = *puVar7;
    if (*(ushort *)(uVar2 + 0x22) <= *(ushort *)(uVar2 + 0x20)) {
      FUN_80017814(uVar2);
      *puVar7 = 0;
    }
  }
LAB_801981b8:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80198230
 * EN v1.0 Address: 0x80198230
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x801981D0
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80198230(int param_1,int param_2)
{
  float fVar1;
  double dVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  ObjGroup_AddObject(param_1,0x48);
  *(byte *)(iVar3 + 0x24) = *(byte *)(param_2 + 0x21) & 0xf | *(byte *)(iVar3 + 0x24) & 0xf0;
  fVar1 = FLOAT_803e4d38;
  *(float *)(iVar3 + 0x10) = FLOAT_803e4d38;
  *(float *)(iVar3 + 0x14) = fVar1;
  dVar2 = DOUBLE_803e4d40;
  *(float *)(iVar3 + 8) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1c)) - DOUBLE_803e4d40);
  *(float *)(iVar3 + 0xc) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - dVar2);
  *(undefined *)(iVar3 + 0x1c) = *(undefined *)(param_2 + 0x1e);
  *(undefined *)(iVar3 + 0x1d) = *(undefined *)(param_2 + 0x1f);
  *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(param_2 + 0x18);
  *(byte *)(iVar3 + 0x25) =
       ((*(byte *)(param_2 + 0x20) & 1) != 0) << 7 | *(byte *)(iVar3 + 0x25) & 0x7f;
  *(byte *)(iVar3 + 0x25) =
       ((*(byte *)(param_2 + 0x20) & 2) != 0) << 5 | *(byte *)(iVar3 + 0x25) & 0xdf;
  *(byte *)(iVar3 + 0x25) =
       ((*(byte *)(param_2 + 0x20) & 4) != 0) << 6 | *(byte *)(iVar3 + 0x25) & 0xbf;
  *(float *)(iVar3 + 0x18) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x22) * 0x3c ^ 0x80000000) -
              DOUBLE_803e4d30);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80198348
 * EN v1.0 Address: 0x80198348
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8019832C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80198348(uint param_1)
{
  FUN_801983a0(param_1);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019836c
 * EN v1.0 Address: 0x8019836C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80198350
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019836c(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801983a0
 * EN v1.0 Address: 0x801983A0
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x80198384
 * EN v1.1 Size: 916b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801983a0(uint param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  short sVar7;
  int iVar6;
  int iVar8;
  undefined4 *puVar9;
  double dVar10;
  undefined auStack_58 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  puVar9 = *(undefined4 **)(param_1 + 0xb8);
  iVar8 = *(int *)(param_1 + 0x4c);
  iVar4 = FUN_80017a98();
  if (iVar4 != 0) {
    if ((int)*(short *)(iVar8 + 0x18) == 0xffffffff) {
      sVar7 = 1;
    }
    else {
      uVar5 = FUN_80017690((int)*(short *)(iVar8 + 0x18));
      sVar7 = (short)uVar5;
    }
    if (sVar7 != 0) {
      if ((*(byte *)(iVar8 + 0x23) & 0x10) == 0) {
        FUN_800068c4(param_1,(ushort)*puVar9);
        FUN_800068c4(param_1,(ushort)puVar9[1]);
      }
      iVar6 = *(int *)(param_1 + 0xf4);
      if (0 < iVar6) {
        if (0 < iVar6) {
          *(uint *)(param_1 + 0xf4) = iVar6 - (uint)DAT_803dc070;
        }
      }
      else {
        fVar1 = *(float *)(param_1 + 0x18) - *(float *)(iVar4 + 0x18);
        fVar2 = *(float *)(param_1 + 0x1c) - *(float *)(iVar4 + 0x1c);
        fVar3 = *(float *)(param_1 + 0x20) - *(float *)(iVar4 + 0x20);
        dVar10 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        uStack_3c = (uint)*(byte *)(iVar8 + 0x20) << 4 ^ 0x80000000;
        local_40 = 0x43300000;
        if (((dVar10 <= (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4d48))
            || (*(byte *)(iVar8 + 0x20) == 0)) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
          dVar10 = DOUBLE_803e4d48;
          for (sVar7 = 0; sVar7 < (short)(ushort)*(byte *)(iVar8 + 0x24); sVar7 = sVar7 + 1) {
            uStack_3c = FUN_80017760(-(uint)*(byte *)(iVar8 + 0x1d),(uint)*(byte *)(iVar8 + 0x1d));
            uStack_3c = uStack_3c ^ 0x80000000;
            local_40 = 0x43300000;
            local_4c = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar10);
            uStack_34 = FUN_80017760(-(uint)*(byte *)(iVar8 + 0x1f),(uint)*(byte *)(iVar8 + 0x1f));
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_48 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar10);
            uStack_2c = FUN_80017760(-(uint)*(byte *)(iVar8 + 0x1e),(uint)*(byte *)(iVar8 + 0x1e));
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_44 = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar10);
            if ((*(byte *)(iVar8 + 0x23) & 1) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,800,auStack_58,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar8 + 0x23) & 2) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x321,auStack_58,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar8 + 0x23) & 4) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x322,auStack_58,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar8 + 0x23) & 8) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x351,auStack_58,4,0xffffffff,0);
            }
          }
        }
        *(uint *)(param_1 + 0xf4) = -(uint)*(byte *)(iVar8 + 0x24);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80198634
 * EN v1.0 Address: 0x80198634
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80198718
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80198634(int param_1)
{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  bVar1 = *(byte *)(*(int *)(param_1 + 0xb8) + 4);
  if ((bVar1 & 1) != 0) {
    *(byte *)(*(int *)(param_1 + 0xb8) + 4) = bVar1 & 0xfe;
    if (*(char *)(iVar2 + 0x1d) == '\x01') {
      if (*(short *)(iVar2 + 0x1a) != 0) {
        FUN_800068cc();
      }
      if (*(short *)(iVar2 + 0x22) != 0) {
        FUN_800068cc();
      }
    }
    else {
      if (*(short *)(iVar2 + 0x1a) != 0) {
        FUN_80006810(param_1,*(short *)(iVar2 + 0x1a));
      }
      if (*(short *)(iVar2 + 0x22) != 0) {
        FUN_80006810(param_1,*(short *)(iVar2 + 0x22));
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801986d4
 * EN v1.0 Address: 0x801986D4
 * EN v1.0 Size: 1668b
 * EN v1.1 Address: 0x801987C4
 * EN v1.1 Size: 1804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801986d4(uint param_1)
{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  uint unaff_r28;
  float *pfVar5;
  int iVar6;
  
  pfVar5 = *(float **)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  if ((*(byte *)(iVar6 + 0x1c) & 8) != 0) {
    iVar3 = FUN_8007f7c0();
    if (iVar3 == 0) {
      iVar3 = FUN_80017a98();
      (**(code **)(*DAT_803dd71c + 0x20))
                ((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                 (double)*(float *)(iVar3 + 0x20),7,(int)*(char *)(iVar6 + 0x20),param_1 + 0xc,
                 param_1 + 0x10,param_1 + 0x14);
    }
    else {
      iVar3 = (**(code **)(*DAT_803dd6d0 + 0xc))();
      (**(code **)(*DAT_803dd71c + 0x20))
                ((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                 (double)*(float *)(iVar3 + 0x20),7,(int)*(char *)(iVar6 + 0x20),param_1 + 0xc,
                 param_1 + 0x10,param_1 + 0x14);
    }
  }
  if (0 < *(short *)(iVar6 + 0x18)) {
    unaff_r28 = FUN_80017690((int)*(short *)(iVar6 + 0x18));
  }
  bVar1 = *(byte *)(iVar6 + 0x1d);
  if (bVar1 == 1) {
    if (((*(short *)(iVar6 + 0x18) == -1) ||
        (((*(byte *)(iVar6 + 0x1c) & 2) != 0 && (unaff_r28 != 0)))) ||
       (((*(byte *)(iVar6 + 0x1c) & 4) != 0 && (unaff_r28 == 0)))) {
      if ((*(byte *)(pfVar5 + 1) & 1) == 0) {
        uVar2 = *(ushort *)(iVar6 + 0x1a);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          uVar4 = param_1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            uVar4 = 0;
          }
          if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_800068d0(uVar4,uVar2);
            }
            else {
              FUN_80006824(uVar4,uVar2);
            }
          }
          else {
            FUN_80006820((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                         (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
          }
        }
        uVar2 = *(ushort *)(iVar6 + 0x22);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_800068d0(param_1,uVar2);
            }
            else {
              FUN_80006824(param_1,uVar2);
            }
          }
          else {
            FUN_80006820((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,uVar2);
          }
        }
      }
    }
    else if ((*(byte *)(pfVar5 + 1) & 1) != 0) {
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0xfe;
      if (*(char *)(iVar6 + 0x1d) == '\x01') {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_800068cc();
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_800068cc();
        }
      }
      else {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_80006810(param_1,*(short *)(iVar6 + 0x1a));
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_80006810(param_1,*(short *)(iVar6 + 0x22));
        }
      }
    }
  }
  else if (bVar1 == 0) {
    if (0 < *(short *)(iVar6 + 0x18)) {
      if (*pfVar5 == 0.0) {
        if ((unaff_r28 != 0) && (*pfVar5 = 1.4013e-45, (*(byte *)(iVar6 + 0x1c) & 2) != 0)) {
          uVar2 = *(ushort *)(iVar6 + 0x1a);
          if (uVar2 != 0) {
            *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
            uVar4 = param_1;
            if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
              uVar4 = 0;
            }
            if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
              if (*(char *)(iVar6 + 0x1d) == '\x01') {
                FUN_800068d0(uVar4,uVar2);
              }
              else {
                FUN_80006824(uVar4,uVar2);
              }
            }
            else {
              FUN_80006820((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                           (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
            }
          }
          uVar2 = *(ushort *)(iVar6 + 0x22);
          if (uVar2 != 0) {
            *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
            if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
              param_1 = 0;
            }
            if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
              if (*(char *)(iVar6 + 0x1d) == '\x01') {
                FUN_800068d0(param_1,uVar2);
              }
              else {
                FUN_80006824(param_1,uVar2);
              }
            }
            else {
              FUN_80006820((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                           (double)*(float *)(param_1 + 0x14),param_1,uVar2);
            }
          }
        }
      }
      else if ((unaff_r28 == 0) && (*pfVar5 = 0.0, (*(byte *)(iVar6 + 0x1c) & 4) != 0)) {
        uVar2 = *(ushort *)(iVar6 + 0x1a);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          uVar4 = param_1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            uVar4 = 0;
          }
          if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_800068d0(uVar4,uVar2);
            }
            else {
              FUN_80006824(uVar4,uVar2);
            }
          }
          else {
            FUN_80006820((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                         (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
          }
        }
        uVar2 = *(ushort *)(iVar6 + 0x22);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_800068d0(param_1,uVar2);
            }
            else {
              FUN_80006824(param_1,uVar2);
            }
          }
          else {
            FUN_80006820((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,uVar2);
          }
        }
      }
    }
  }
  else if (bVar1 < 3) {
    if (((*(short *)(iVar6 + 0x18) == -1) ||
        (((*(byte *)(iVar6 + 0x1c) & 2) != 0 && (unaff_r28 != 0)))) ||
       (((*(byte *)(iVar6 + 0x1c) & 4) != 0 && (unaff_r28 == 0)))) {
      *pfVar5 = *pfVar5 - FLOAT_803dc074;
      if (*pfVar5 <= FLOAT_803e4d50) {
        uVar4 = FUN_80017760((uint)*(byte *)(iVar6 + 0x1e),(uint)*(byte *)(iVar6 + 0x1f));
        *pfVar5 = FLOAT_803e4d54 *
                  (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e4d58);
        uVar2 = *(ushort *)(iVar6 + 0x1a);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          uVar4 = param_1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            uVar4 = 0;
          }
          if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_800068d0(uVar4,uVar2);
            }
            else {
              FUN_80006824(uVar4,uVar2);
            }
          }
          else {
            FUN_80006820((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                         (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
          }
        }
        uVar2 = *(ushort *)(iVar6 + 0x22);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_800068d0(param_1,uVar2);
            }
            else {
              FUN_80006824(param_1,uVar2);
            }
          }
          else {
            FUN_80006820((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,uVar2);
          }
        }
      }
    }
    else if ((*(byte *)(pfVar5 + 1) & 1) != 0) {
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0xfe;
      if (*(char *)(iVar6 + 0x1d) == '\x01') {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_800068cc();
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_800068cc();
        }
      }
      else {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_80006810(param_1,*(short *)(iVar6 + 0x1a));
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_80006810(param_1,*(short *)(iVar6 + 0x22));
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80198d58
 * EN v1.0 Address: 0x80198D58
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x80198ED0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80198d58(int param_1,int param_2)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  bVar1 = *(byte *)(param_2 + 0x1d);
  if (bVar1 != 1) {
    if (bVar1 == 0) {
      if (0 < *(short *)(param_2 + 0x18)) {
        fVar2 = (float)FUN_80017690((int)*(short *)(param_2 + 0x18));
        *pfVar4 = fVar2;
      }
    }
    else if (bVar1 < 3) {
      uVar3 = FUN_80017760((uint)*(byte *)(param_2 + 0x1e),(uint)*(byte *)(param_2 + 0x1f));
      *pfVar4 = FLOAT_803e4d54 *
                (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e4d58);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80198e08
 * EN v1.0 Address: 0x80198E08
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x80198F7C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80198e08(void)
{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  undefined8 extraout_f1;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar8;
  undefined4 local_28;
  float local_24;
  longlong local_20;
  
  uVar8 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  uVar4 = (undefined4)uVar8;
  local_28 = 0x17;
  iVar5 = *(int *)(iVar1 + 0xb8);
  uVar2 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(iVar5 + 0x28),(double)*(float *)(iVar5 + 0x2c),
                     (double)*(float *)(iVar5 + 0x30),&local_28,1,
                     (int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x38));
  iVar3 = (**(code **)(*DAT_803dd71c + 0x4c))
                    ((double)*(float *)(iVar5 + 0x28),(double)*(float *)(iVar5 + 0x2c),
                     (double)*(float *)(iVar5 + 0x30),uVar2,&local_24);
  dVar6 = (double)*(float *)(iVar5 + 0x20);
  dVar7 = (double)*(float *)(iVar5 + 0x24);
  iVar5 = (**(code **)(*DAT_803dd71c + 0x4c))((double)*(float *)(iVar5 + 0x1c),uVar2,&local_24);
  if (iVar3 == 0) {
    if (iVar5 == 0) {
      local_20 = (longlong)(int)local_24;
      FUN_801993b0(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,0xfffffffe,
                   (int)local_24,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      local_20 = (longlong)(int)local_24;
      FUN_801993b0(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,0xffffffff,
                   (int)local_24,in_r7,in_r8,in_r9,in_r10);
    }
  }
  else if (iVar5 == 0) {
    local_20 = (longlong)(int)local_24;
    FUN_801993b0(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,1,(int)local_24,
                 in_r7,in_r8,in_r9,in_r10);
  }
  else {
    local_20 = (longlong)(int)local_24;
    FUN_801993b0(extraout_f1,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,uVar4,2,(int)local_24,
                 in_r7,in_r8,in_r9,in_r10);
  }
  FUN_8028688c();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_80197E04(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_80197DA8(void) { return 0x8; }
int fn_80198194(void) { return 0x8; }
