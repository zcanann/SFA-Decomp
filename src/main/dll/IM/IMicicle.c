#include "ghidra_import.h"
#include "main/dll/IM/IMicicle.h"

extern undefined8 FUN_80006724();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006958();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017738();
extern undefined4 FUN_80017744();
extern uint FUN_80017760();
extern undefined4 FUN_800178b8();
extern undefined4 FUN_80017a50();
extern undefined4 FUN_80017a7c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined8 FUN_80017ac8();
extern int FUN_80017af8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern int FUN_80056600();
extern undefined4 FUN_800632d8();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_80080f3c();
extern undefined4 FUN_8017c5c4();
extern undefined4 FUN_801a35f4();
extern undefined4 FUN_801d8308();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80286830();
extern int FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern byte FUN_80294c20();
extern undefined4 FUN_80294c30();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2a68;
extern undefined4 DAT_802c2a6c;
extern undefined4 DAT_802c2a70;
extern int DAT_803239f0;
extern undefined4 DAT_803239fd;
extern undefined4 DAT_80323b28;
extern undefined4 DAT_80323b30;
extern undefined4 DAT_80323b3c;
extern short DAT_80323c58;
extern undefined4 DAT_803dcafc;
extern undefined4 DAT_803dcb00;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5020;
extern f64 DOUBLE_803e5048;
extern f64 DOUBLE_803e5060;
extern f64 DOUBLE_803e5078;
extern f64 DOUBLE_803e5090;
extern f64 DOUBLE_803e50a8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dcaf8;
extern f32 FLOAT_803e4ff4;
extern f32 FLOAT_803e5028;
extern f32 FLOAT_803e502c;
extern f32 FLOAT_803e5030;
extern f32 FLOAT_803e5034;
extern f32 FLOAT_803e5038;
extern f32 FLOAT_803e5040;
extern f32 FLOAT_803e5050;
extern f32 FLOAT_803e5058;
extern f32 FLOAT_803e5074;
extern f32 FLOAT_803e5080;
extern f32 FLOAT_803e5084;
extern f32 FLOAT_803e5088;
extern f32 FLOAT_803e508c;
extern f32 FLOAT_803e5098;
extern f32 FLOAT_803e509c;
extern f32 FLOAT_803e50a0;

/*
 * --INFO--
 *
 * Function: FUN_801a39d0
 * EN v1.0 Address: 0x801A39D0
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801A3B20
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a39d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar2 = -1;
  iVar3 = *(int *)(param_9 + 0xb8);
  uVar5 = ObjGroup_RemoveObject(param_9,0x21);
  if (param_10 == 0) {
    iVar3 = iVar3 + -4;
    while( true ) {
      iVar4 = iVar3 + 4;
      iVar2 = iVar2 + 1;
      if (0xe < iVar2) break;
      piVar1 = (int *)(iVar3 + 0x694);
      iVar3 = iVar4;
      if (*piVar1 != 0) {
        uVar5 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a3ac0
 * EN v1.0 Address: 0x801A3AC0
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x801A3B9C
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3ac0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  if (*(char *)(iVar3 + 0x6e4) != '\x02') {
    if (*(char *)(iVar3 + 0x6e4) == '\0') {
      uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x40));
      if (uVar1 != 0) {
        FUN_801a35f4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar5,0
                     ,iVar3,in_r7,in_r8,in_r9,in_r10);
        if (*(int *)(iVar3 + 0x6d0) != 0) {
          FUN_80006824(param_9,(ushort)*(int *)(iVar3 + 0x6d0));
        }
        *(undefined *)(iVar3 + 0x6e4) = 1;
        *(undefined *)(param_9 + 0x36) = 0;
      }
    }
    else {
      iVar4 = 0;
      iVar6 = iVar3;
      do {
        if (*(int *)(iVar6 + 0x690) != 0) {
          iVar2 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x690) + 0x68) + 0x20))();
          if (iVar2 != 1) {
            if (iVar2 < 1) {
              if (-1 < iVar2) {
                FUN_80017698((int)*(short *)(iVar5 + 0x3e),1);
                if ((*(uint *)(iVar3 + 0x6cc) & 1 << iVar4) == 0) {
                  *(uint *)(iVar3 + 0x6cc) = *(uint *)(iVar3 + 0x6cc) | 1 << iVar4;
                }
              }
            }
            else if (iVar2 < 3) {
              uVar7 = FUN_80017698((int)*(short *)(iVar5 + 0x3e),1);
              FUN_80017ac8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(iVar6 + 0x690));
              *(undefined4 *)(iVar6 + 0x690) = 0;
            }
          }
        }
        iVar6 = iVar6 + 4;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0xf);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a3cc4
 * EN v1.0 Address: 0x801A3CC4
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x801A3CF0
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3cc4(undefined2 *param_1,int param_2)
{
  char cVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  ObjGroup_AddObject((int)param_1,0x21);
  iVar5 = *(int *)(param_1 + 0x5c);
  cVar1 = *(char *)(param_2 + 0x18);
  if (cVar1 == '\0') {
    cVar1 = '\x01';
  }
  *(char *)(iVar5 + 0x6d4) = cVar1;
  *(undefined4 *)(iVar5 + 0x6cc) = 0;
  *(undefined4 *)(iVar5 + 0x690) = 0;
  *(undefined4 *)(iVar5 + 0x694) = 0;
  *(undefined4 *)(iVar5 + 0x698) = 0;
  *(undefined4 *)(iVar5 + 0x69c) = 0;
  *(undefined4 *)(iVar5 + 0x6a0) = 0;
  *(undefined4 *)(iVar5 + 0x6a4) = 0;
  *(undefined4 *)(iVar5 + 0x6a8) = 0;
  *(undefined4 *)(iVar5 + 0x6ac) = 0;
  *(undefined4 *)(iVar5 + 0x6b0) = 0;
  *(undefined4 *)(iVar5 + 0x6b4) = 0;
  *(undefined4 *)(iVar5 + 0x6b8) = 0;
  *(undefined4 *)(iVar5 + 0x6bc) = 0;
  *(undefined4 *)(iVar5 + 0x6c0) = 0;
  *(undefined4 *)(iVar5 + 0x6c4) = 0;
  *(undefined4 *)(iVar5 + 0x6c8) = 0;
  *param_1 = *(undefined2 *)(param_2 + 0x1a);
  param_1[1] = *(undefined2 *)(param_2 + 0x1c);
  param_1[2] = *(undefined2 *)(param_2 + 0x1e);
  uVar2 = FUN_80017690((int)*(short *)(param_2 + 0x3e));
  if (uVar2 != 0) {
    *(undefined *)(iVar5 + 0x6e4) = 2;
  }
  cVar1 = '\0';
  piVar4 = &DAT_803239f0;
  iVar6 = 2;
  do {
    iVar3 = (int)(short)param_1[0x23];
    if (iVar3 == *piVar4) {
      *(char *)(iVar5 + 0x6e5) = cVar1;
      break;
    }
    if (iVar3 == piVar4[4]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x01';
      break;
    }
    if (iVar3 == piVar4[8]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x02';
      break;
    }
    if (iVar3 == piVar4[0xc]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x03';
      break;
    }
    if (iVar3 == piVar4[0x10]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x04';
      break;
    }
    if (iVar3 == piVar4[0x14]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x05';
      break;
    }
    if (iVar3 == piVar4[0x18]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x06';
      break;
    }
    if (iVar3 == piVar4[0x1c]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\a';
      break;
    }
    piVar4 = piVar4 + 0x20;
    cVar1 = cVar1 + '\b';
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  if (*(char *)(param_2 + 0x3d) == '\0') {
    *(undefined *)(param_2 + 0x3d) = 0x14;
  }
  *(float *)(param_1 + 4) =
       (*(float *)(*(int *)(param_1 + 0x28) + 4) *
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x3d) ^ 0x80000000) -
              DOUBLE_803e5020)) / FLOAT_803e4ff4;
  if (((&DAT_803239fd)[(uint)*(byte *)(iVar5 + 0x6e5) * 0x10] & 1) != 0) {
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a3ee8
 * EN v1.0 Address: 0x801A3EE8
 * EN v1.0 Size: 936b
 * EN v1.1 Address: 0x801A3F84
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3ee8(void)
{
  int iVar1;
  char cVar2;
  float fVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  double dVar11;
  double in_f24;
  double dVar12;
  double in_f25;
  double dVar13;
  double in_f26;
  double dVar14;
  double in_f27;
  double dVar15;
  double in_f28;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double dVar17;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_138;
  float local_134;
  float local_130;
  undefined auStack_12c [12];
  float local_120;
  float local_11c;
  float local_118;
  float afStack_114 [13];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined4 local_d0;
  uint uStack_cc;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined4 local_b8;
  uint uStack_b4;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  puVar4 = (ushort *)FUN_80286830();
  fVar3 = FLOAT_803e5028;
  iVar8 = *(int *)(puVar4 + 0x26);
  pbVar7 = *(byte **)(puVar4 + 0x5c);
  *(float *)(puVar4 + 0x16) = FLOAT_803e5028;
  *(float *)(puVar4 + 0x14) = fVar3;
  *(float *)(puVar4 + 0x12) = fVar3;
  uVar5 = FUN_80017690((int)*(short *)(iVar8 + 0x1e));
  if (uVar5 != 0) {
    if ((char)*pbVar7 < '\0') {
      uVar5 = FUN_80017690((int)*(short *)(iVar8 + 0x20));
      *pbVar7 = (byte)((uVar5 & 0xff) << 7) | *pbVar7 & 0x7f;
    }
    else {
      cVar2 = *(char *)(iVar8 + 0x19);
      uVar5 = countLeadingZeros(((uint)(byte)((*(float *)(pbVar7 + 4) == FLOAT_803e5028) << 1) <<
                                0x1c) >> 0x1d ^ 1);
      fVar3 = FLOAT_803e502c;
      if (uVar5 >> 5 == 0) {
        fVar3 = FLOAT_803e5030 * *(float *)(pbVar7 + 4);
      }
      dVar14 = (double)fVar3;
      FUN_80017a50(puVar4,afStack_114,'\0');
      dVar15 = DOUBLE_803e5048;
      local_e0 = (double)CONCAT44(0x43300000,(int)(short)puVar4[2] ^ 0x80000000);
      iVar6 = (int)(FLOAT_803e5034 * FLOAT_803dc074 + (float)(local_e0 - DOUBLE_803e5048));
      local_d8 = (double)(longlong)iVar6;
      puVar4[2] = (ushort)iVar6;
      iVar6 = ((int)cVar2 % 3) * 0x18;
      puVar10 = (undefined4 *)(&DAT_80323b28 + iVar6);
      dVar16 = (double)FLOAT_803e5040;
      dVar17 = (double)FLOAT_803e5038;
      dVar13 = (double)FLOAT_803e5028;
      for (iVar9 = -0x7fff; iVar9 < 0x7fff; iVar9 = iVar9 + *(int *)(&DAT_80323b30 + iVar6)) {
        uVar5 = FUN_80017760(-DAT_803dcafc,DAT_803dcafc);
        local_d8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        dVar12 = (double)(float)(local_d8 - dVar15);
        iVar1 = (int)(dVar16 * (double)*(float *)(&DAT_80323b3c + iVar6));
        local_e0 = (double)(longlong)iVar1;
        uStack_cc = iVar9 + iVar1 ^ 0x80000000;
        local_d0 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        local_138 = (float)((double)(float)(dVar17 * (double)(float)(dVar14 * (double)FLOAT_803dcaf8
                                                                    )) * dVar11 + dVar12);
        uVar5 = FUN_80017760(-DAT_803dcafc,DAT_803dcafc);
        local_c8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        dVar12 = (double)(float)(local_c8 - dVar15);
        iVar1 = (int)(dVar16 * (double)*(float *)(&DAT_80323b3c + iVar6));
        local_c0 = (double)(longlong)iVar1;
        uStack_b4 = iVar9 + iVar1 ^ 0x80000000;
        local_b8 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        local_134 = (float)((double)(float)(dVar17 * (double)(float)(dVar14 * (double)FLOAT_803dcaf8
                                                                    )) * dVar11 + dVar12);
        local_130 = (float)dVar13;
        FUN_80247cd8(afStack_114,&local_138,&local_138);
        local_120 = local_138 + *(float *)(puVar4 + 6);
        local_11c = local_134 + *(float *)(puVar4 + 8);
        local_118 = local_130 + *(float *)(puVar4 + 10);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
      }
      uVar5 = FUN_8007f6c8((float *)(pbVar7 + 4));
      if (uVar5 == 0) {
        uVar5 = FUN_80017690((int)*(short *)(iVar8 + 0x20));
        if (uVar5 != 0) {
          FUN_8007f718((float *)(pbVar7 + 4),0x3c);
          FUN_80006824((uint)puVar4,0x366);
          if (*(int *)(*(int *)(puVar4 + 0x26) + 0x14) != 0x47f5e) {
            FUN_80006824((uint)puVar4,0x409);
          }
        }
      }
      else {
        uStack_b4 = DAT_803dcb00 ^ 0x80000000;
        local_b8 = 0x43300000;
        local_c0 = (double)CONCAT44(0x43300000,(int)(short)puVar4[1] ^ 0x80000000);
        iVar8 = (int)((float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e5048) *
                      FLOAT_803dc074 + (float)(local_c0 - DOUBLE_803e5048));
        local_c8 = (double)(longlong)iVar8;
        puVar4[1] = (ushort)iVar8;
        iVar8 = FUN_8007f764((float *)(pbVar7 + 4));
        if (iVar8 != 0) {
          *pbVar7 = *pbVar7 & 0x7f | 0x80;
          puVar4[1] = 0;
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4290
 * EN v1.0 Address: 0x801A4290
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801A43EC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4290(undefined2 *param_1,int param_2)
{
  uint uVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x20));
  *pbVar2 = (byte)((uVar1 & 0xff) << 7) | *pbVar2 & 0x7f;
  FUN_8007f6e4((undefined4 *)(pbVar2 + 4));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a42e8
 * EN v1.0 Address: 0x801A42E8
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x801A4450
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a42e8(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  byte *pbVar6;
  bool bVar7;
  bool bVar8;
  double dVar9;
  
  iVar2 = FUN_80286840();
  iVar3 = FUN_80017a98();
  iVar4 = FUN_80017a90();
  if (iVar3 == 0) {
    bVar7 = false;
  }
  else {
    dVar9 = (double)FUN_80017710((float *)(iVar2 + 0x18),(float *)(iVar3 + 0x18));
    bVar7 = dVar9 < (double)FLOAT_803e5050;
  }
  if (iVar4 == 0) {
    bVar8 = false;
  }
  else {
    dVar9 = (double)FUN_80017710((float *)(iVar2 + 0x18),(float *)(iVar4 + 0x18));
    bVar8 = dVar9 < (double)FLOAT_803e5050;
  }
  pbVar6 = *(byte **)(iVar2 + 0xb8);
  iVar2 = *(int *)(iVar2 + 0x4c);
  if (*pbVar6 >> 5 == 0) {
    uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x18));
    if (((uVar5 != 0) &&
        (((int)*(short *)(iVar2 + 0x22) == 0xffffffff ||
         (uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x22)), uVar5 != 0)))) &&
       ((FUN_80017698((int)*(short *)(iVar2 + 0x1a),1), bVar7 || (bVar8)))) {
      *pbVar6 = *pbVar6 & 0x1f | 0x40;
    }
  }
  else if (((*pbVar6 >> 5 == 1) &&
           (((uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x18)), uVar5 != 0 ||
             (((int)*(short *)(iVar2 + 0x22) != 0xffffffff &&
              (uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x22)), uVar5 != 0)))) && (!bVar7)))) &&
          (!bVar8)) {
    *pbVar6 = *pbVar6 & 0x1f | 0x60;
  }
  bVar1 = *pbVar6;
  if (bVar1 >> 5 == 2) {
    if (*(char *)(param_3 + 0x80) == '\x02') {
      *pbVar6 = bVar1 & 0x1f | 0x20;
    }
  }
  else if ((bVar1 >> 5 == 3) && (*(char *)(param_3 + 0x80) == '\x01')) {
    *pbVar6 = bVar1 & 0x1f;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a44f8
 * EN v1.0 Address: 0x801A44F8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A462C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a44f8(int param_1)
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
 * Function: FUN_801a4520
 * EN v1.0 Address: 0x801A4520
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801A4660
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4520(int param_1)
{
  int iVar1;
  
  if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = *(int *)(param_1 + 0x4c);
    if ((*(short *)(iVar1 + 0x1c) != 0) && (**(byte **)(param_1 + 0xb8) >> 5 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x54))();
    }
    iVar1 = (int)*(char *)(iVar1 + 0x1e);
    if (iVar1 != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(iVar1,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a45cc
 * EN v1.0 Address: 0x801A45CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A4708
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45cc(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a45d0
 * EN v1.0 Address: 0x801A45D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A478C
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45d0(short *param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: cflevelcontrol_free
 * EN v1.0 Address: 0x801A45D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A4880
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cflevelcontrol_free(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x1e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a45f8
 * EN v1.0 Address: 0x801A45F8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A48A4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45f8(int param_1)
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
 * Function: FUN_801a4620
 * EN v1.0 Address: 0x801A4620
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801A48DC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4620(undefined2 *param_1,int param_2)
{
  ObjGroup_AddObject((int)param_1,0x1e);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a466c
 * EN v1.0 Address: 0x801A466C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A4948
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a466c(int param_1)
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
 * Function: FUN_801a4694
 * EN v1.0 Address: 0x801A4694
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801A497C
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4694(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  iVar5 = *(int *)(param_1 + 0x26);
  iVar1 = FUN_80017a98();
  uVar4 = 0xff;
  uVar2 = FUN_80017690((int)*(short *)(iVar5 + 0x20));
  if (uVar2 != 0) {
    iVar3 = Obj_GetYawDeltaToObject(param_1,iVar1,(float *)0x0);
    iVar3 = (int)(short)iVar3;
    if (iVar3 < 0) {
      iVar3 = -iVar3;
    }
    if (iVar3 < 0x4001) {
      dVar8 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1a) ^ 0x80000000
                                              ) - DOUBLE_803e5078);
      dVar6 = (double)FUN_8001771c((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      dVar7 = (double)FUN_80006958((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                                   (double)*(float *)(param_1 + 10));
      if (dVar7 < dVar6) {
        dVar6 = (double)FUN_80006958((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8)
                                     ,(double)*(float *)(param_1 + 10));
      }
      if (dVar6 < dVar8) {
        uVar4 = (undefined)(int)(FLOAT_803e5074 * (float)(dVar6 / dVar8));
      }
      *(undefined *)(param_1 + 0x1b) = uVar4;
    }
    else {
      *(undefined *)(param_1 + 0x1b) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4810
 * EN v1.0 Address: 0x801A4810
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801A4AD8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a4810(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,undefined4 param_10,int param_11)
{
  undefined4 uVar1;
  int iVar2;
  undefined8 uVar3;
  
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
    if (*(char *)(param_11 + iVar2 + 0x81) == '\x01') {
      FUN_80017698(0xdcb,1);
      uVar3 = FUN_80017698(0x4a3,0);
      FUN_80041ff8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2b);
      FUN_80042b9c(0,0,1);
      uVar1 = FUN_80044404(0x2b);
      FUN_80042bec(uVar1,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4924
 * EN v1.0 Address: 0x801A4924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A4B8C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4924(int param_1)
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
 * Function: FUN_801a494c
 * EN v1.0 Address: 0x801A494C
 * EN v1.0 Size: 2272b
 * EN v1.1 Address: 0x801A4BC0
 * EN v1.1 Size: 1516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a494c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  int iVar3;
  char cVar6;
  uint uVar4;
  uint uVar5;
  byte bVar7;
  undefined uVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar1 = FUN_80286840();
  iVar9 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  local_28 = DAT_802c2a68;
  local_24 = DAT_802c2a6c;
  local_20 = DAT_802c2a70;
  if ((*(byte *)(iVar9 + 0xc) >> 3 & 1) != 0) {
    iVar3 = FUN_80017af8(0x47fae);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x47f83);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x47f8f);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x47fa2);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29f2);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29f3);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29ef);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29ee);
    FUN_8017c5c4(iVar3);
    *(byte *)(iVar9 + 0xc) = *(byte *)(iVar9 + 0xc) & 0xf7;
  }
  cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(0x1d);
  uVar10 = extraout_f1;
  if ((cVar6 == '\x01') && (uVar4 = FUN_80017690(0x40), uVar4 != 0)) {
    uVar10 = (**(code **)(*DAT_803dd72c + 0x44))(0x1d,2);
  }
  uVar4 = FUN_80017690(0x974);
  uVar4 = uVar4 & 0xff;
  uVar5 = FUN_80017690(0x975);
  uVar5 = uVar5 & 0xff;
  bVar7 = *(byte *)(iVar9 + 0xc) >> 5 & 1;
  if ((bVar7 == 0) || ((*(byte *)(iVar9 + 0xc) >> 4 & 1) == 0)) {
    if ((bVar7 == 0) && ((*(byte *)(iVar9 + 0xc) >> 4 & 1) == 0)) {
      if ((uVar4 != 0) || (uVar5 != 0)) {
        uVar10 = FUN_80006824(0,0x109);
      }
    }
    else if ((uVar4 != 0) && (uVar5 != 0)) {
      uVar10 = FUN_80006824(0,0x7e);
    }
  }
  *(byte *)(iVar9 + 0xc) = (byte)(uVar4 << 5) & 0x20 | *(byte *)(iVar9 + 0xc) & 0xdf;
  *(byte *)(iVar9 + 0xc) = (byte)(uVar5 << 4) & 0x10 | *(byte *)(iVar9 + 0xc) & 0xef;
  if (*(int *)(iVar1 + 0xf4) == 0) {
    uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                          ,0x56,0,in_r7,in_r8,in_r9,in_r10);
    uVar4 = FUN_80017690(0xd73);
    if (uVar4 == 0) {
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0xd,0,in_r7,in_r8,in_r9,in_r10);
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0x11,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0xe,0,
                   in_r7,in_r8,in_r9,in_r10);
      FUN_80080f3c((double)FLOAT_803e5084,0);
      uVar10 = FUN_80017698(0xd73,1);
    }
    uVar4 = FUN_80017690(0xdca);
    if (uVar4 != 0) {
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0xd,0,in_r7,in_r8,in_r9,in_r10);
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0x7e,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0x7d,0
                   ,in_r7,in_r8,in_r9,in_r10);
      FUN_80080f3c((double)FLOAT_803e5084,1);
      FUN_80017698(0xdca,0);
      FUN_80042b9c(0,0,1);
    }
    *(undefined4 *)(iVar1 + 0xf4) = 1;
  }
  uVar4 = FUN_80017690(0x94f);
  if ((uVar4 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
    FUN_80017698(0x94e,0);
  }
  uVar4 = FUN_80017690(0x94e);
  if ((uVar4 == 0) || (bVar7 = FUN_80294c20(iVar2), bVar7 != 0)) {
    if ((uVar4 == 0) && (bVar7 = FUN_80294c20(iVar2), bVar7 == 0)) {
      iVar2 = FUN_80017a98();
      FUN_80294c30(iVar2,1);
    }
  }
  else {
    iVar2 = FUN_80017a98();
    FUN_80294c30(iVar2,0);
  }
  uVar4 = FUN_80017690(0xd3d);
  if (uVar4 != 0) {
    iVar2 = FUN_80056600();
    iVar3 = *DAT_803dd72c;
    (**(code **)(iVar3 + 0x24))(&local_28,0,iVar2,1);
    uVar10 = FUN_80017698(0xd3d,0);
    uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                          ,0xd,0,iVar3,in_r8,in_r9,in_r10);
    FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0x11,0,
                 iVar3,in_r8,in_r9,in_r10);
    FUN_80080f3c((double)FLOAT_803e5080,1);
  }
  iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if (iVar1 == 0x47) {
    if (*(char *)(iVar9 + 0xd) != 'G') {
      FUN_80017698(0xc0,1);
    }
  }
  else if (*(char *)(iVar9 + 0xd) == 'G') {
    FUN_80017698(0x1a8,1);
  }
  uVar8 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  *(undefined *)(iVar9 + 0xd) = uVar8;
  FUN_801d8308(iVar9 + 8,4,-1,-1,0x983,(int *)0xb0);
  FUN_801d8308(iVar9 + 8,8,-1,-1,0x983,(int *)0x38);
  FUN_801d8480(iVar9 + 8,0x100,-1,-1,0x983,(int *)0x16);
  FUN_801d8480(iVar9 + 8,0x80,-1,-1,0x983,(int *)0x39);
  uVar4 = FUN_80017690(0x983);
  if (uVar4 == 0) {
    uVar4 = FUN_80017690(0xe23);
    if (uVar4 == 0) {
      FUN_801d8480(iVar9 + 8,0x200,-1,-1,0x984,(int *)0xad);
      FUN_801d8308(iVar9 + 8,0x40,-1,-1,0x984,(int *)0x16);
    }
    uVar4 = FUN_80017690(0x984);
    if (uVar4 != 0) {
      FUN_801d8308(iVar9 + 8,0x20,-1,-1,0xe23,(int *)0x17);
      FUN_801d8480(iVar9 + 8,0x400,-1,-1,0xe23,(int *)0x16);
    }
  }
  FUN_801d8308(iVar9 + 8,1,0x1a8,0xc0,0xdb8,(int *)0xae);
  FUN_801d8308(iVar9 + 8,0x10,-1,-1,0xe1d,(int *)0x36);
  FUN_801d8308(iVar9 + 8,0x1000,-1,-1,0xe1d,(int *)0xf1);
  FUN_801d8308(iVar9 + 8,2,-1,-1,0xb46,(int *)0xaf);
  FUN_801d8308(iVar9 + 8,0x800,-1,-1,0xcbb,(int *)0xc4);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a522c
 * EN v1.0 Address: 0x801A522C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A51AC
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a522c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a5230
 * EN v1.0 Address: 0x801A5230
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801A536C
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5230(undefined4 param_1,undefined4 param_2,int param_3,float *param_4)
{
  float fVar1;
  double dVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar7 = FUN_80286840();
  puVar3 = (undefined2 *)((ulonglong)uVar7 >> 0x20);
  iVar4 = (int)uVar7;
  *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar4 + 8);
  *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar4 + 0xc);
  *(undefined4 *)(puVar3 + 10) = *(undefined4 *)(iVar4 + 0x10);
  fVar1 = FLOAT_803e5088;
  if (param_3 == 0) {
    *param_4 = FLOAT_803e5088;
    param_4[1] = fVar1;
    param_4[2] = fVar1;
    local_40 = fVar1;
    local_3c = fVar1;
    local_38 = fVar1;
    iVar5 = **(int **)(*(int *)(puVar3 + 0x3e) + (uint)*(byte *)(iVar4 + 0x18) * 4);
    for (iVar6 = 0; dVar2 = DOUBLE_803e5090, fVar1 = FLOAT_803e508c,
        uStack_2c = (uint)*(ushort *)(iVar5 + 0xe4), iVar6 < (int)uStack_2c; iVar6 = iVar6 + 1) {
      FUN_800178b8(iVar5,iVar6,&local_4c);
      local_40 = local_4c + local_40;
      local_3c = local_48 + local_3c;
      local_38 = local_44 + local_38;
    }
    local_30 = 0x43300000;
    *param_4 = local_40 *
               (FLOAT_803e508c / (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5090));
    uStack_24 = (uint)*(ushort *)(iVar5 + 0xe4);
    local_28 = 0x43300000;
    param_4[1] = local_3c * (fVar1 / (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2));
    uStack_1c = (uint)*(ushort *)(iVar5 + 0xe4);
    local_20 = 0x43300000;
    param_4[2] = local_38 * (fVar1 / (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2));
  }
  param_4[3] = *param_4;
  param_4[4] = param_4[1];
  param_4[5] = param_4[2];
  FUN_801a5420(puVar3,(int)param_4,iVar4);
  local_58 = *param_4;
  local_54 = param_4[1];
  local_50 = param_4[2];
  FUN_80017744(puVar3,&local_58);
  fVar1 = *(float *)(puVar3 + 4);
  local_58 = local_58 * fVar1;
  local_54 = local_54 * fVar1;
  local_50 = local_50 * fVar1;
  *(undefined *)((int)param_4 + 0x67) = 0xff;
  *(undefined *)((int)param_4 + 0x66) = 0;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a5420
 * EN v1.0 Address: 0x801A5420
 * EN v1.0 Size: 724b
 * EN v1.1 Address: 0x801A5544
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5420(undefined2 *param_1,int param_2,int param_3)
{
  float fVar1;
  double dVar2;
  int iVar3;
  uint uVar4;
  float local_48 [2];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_48[0] = FLOAT_803e5088;
  *param_1 = *(undefined2 *)(param_3 + 0x1a);
  param_1[1] = *(undefined2 *)(param_3 + 0x1c);
  param_1[2] = *(undefined2 *)(param_3 + 0x1e);
  dVar2 = DOUBLE_803e50a8;
  fVar1 = FLOAT_803e5098;
  uStack_3c = (int)*(short *)(param_3 + 0x20) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_1 + 0x12) =
       (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e50a8) / FLOAT_803e5098;
  uStack_34 = (int)*(short *)(param_3 + 0x22) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_1 + 0x14) = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar2) / fVar1;
  uStack_2c = (int)*(short *)(param_3 + 0x24) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_1 + 0x16) = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar2) / fVar1;
  uStack_24 = (int)*(short *)(param_3 + 0x2c) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x18) = (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2);
  uStack_1c = (int)*(short *)(param_3 + 0x2e) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x1c) = (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2);
  uStack_14 = (int)*(short *)(param_3 + 0x30) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x20) = (float)((double)CONCAT44(0x43300000,uStack_14) - dVar2);
  if (*(short *)(param_3 + 0x3a) == 0) {
    FUN_800632d8((double)*(float *)(param_1 + 6),(double)(*(float *)(param_1 + 8) - FLOAT_803e509c),
                 (double)*(float *)(param_1 + 10),param_1,local_48,0);
    *(float *)(param_2 + 0x54) = *(float *)(param_1 + 8) - local_48[0];
  }
  else {
    *(float *)(param_2 + 0x54) =
         *(float *)(param_1 + 8) +
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x3a) ^ 0x80000000) - dVar2);
  }
  dVar2 = DOUBLE_803e50a8;
  fVar1 = FLOAT_803e509c;
  uStack_14 = (int)*(short *)(param_3 + 0x32) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x24) =
       (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e50a8) / FLOAT_803e509c;
  uStack_1c = (int)*(short *)(param_3 + 0x34) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x28) = (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2) / fVar1;
  uStack_24 = (int)*(short *)(param_3 + 0x36) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x2c) = (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2) / fVar1;
  fVar1 = FLOAT_803e50a0;
  uStack_2c = (int)*(short *)(param_3 + 0x26) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_2 + 0x30) =
       (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar2) / FLOAT_803e50a0;
  uStack_34 = (int)*(short *)(param_3 + 0x28) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_2 + 0x34) = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar2) / fVar1;
  uStack_3c = (int)*(short *)(param_3 + 0x2a) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_2 + 0x38) = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar2) / fVar1;
  *(undefined4 *)(param_2 + 0x58) = 0;
  if (*(short *)(param_3 + 0x38) == 0) {
    *(undefined4 *)(param_2 + 0x5c) = 0xffffffff;
  }
  else {
    uVar4 = FUN_80017760(0,100);
    iVar3 = (uint)*(ushort *)(param_3 + 0x38) * (uVar4 + 100);
    iVar3 = iVar3 / 200 + (iVar3 >> 0x1f);
    *(int *)(param_2 + 0x5c) = iVar3 - (iVar3 >> 0x1f);
  }
  return;
}
