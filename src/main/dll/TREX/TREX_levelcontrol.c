#include "ghidra_import.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068fc();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined8 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017a28();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_800388b4();
extern undefined4 FUN_8008112c();
extern uint FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd708;
extern f32 FLOAT_803e6520;
extern f32 FLOAT_803e6524;
extern f32 FLOAT_803e6528;
extern f32 FLOAT_803e652c;
extern f32 FLOAT_803e6530;
extern f32 FLOAT_803e6534;
extern f32 FLOAT_803e6538;
extern f32 FLOAT_803e653c;
extern f32 FLOAT_803e6540;
extern f32 FLOAT_803e6544;

/*
 * --INFO--
 *
 * Function: FUN_801e34c0
 * EN v1.0 Address: 0x801E34C0
 * EN v1.0 Size: 2312b
 * EN v1.1 Address: 0x801E3AB0
 * EN v1.1 Size: 2132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e34c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  undefined2 *puVar9;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar10;
  int iVar11;
  undefined8 uVar12;
  double dVar13;
  double in_f29;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double dVar16;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_88;
  int local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  ushort local_68 [4];
  float local_60;
  float local_5c;
  float local_58;
  float local_54 [11];
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
  uVar3 = FUN_8028683c();
  iVar4 = FUN_80017a98();
  piVar10 = *(int **)(uVar3 + 0xb8);
  iVar11 = *(int *)(uVar3 + 0x4c);
  if (*(short *)(*(int *)(uVar3 + 0x30) + 0x46) == 0x139) {
    *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) = *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) & 0xfffe
    ;
    *(undefined *)((int)piVar10 + 0xd) = 0;
  }
  else {
    if (*piVar10 == 0) {
      iVar5 = FUN_80017b00(&local_84,&local_88);
      for (; local_84 < local_88; local_84 = local_84 + 1) {
        iVar6 = *(int *)(iVar5 + local_84 * 4);
        if (*(short *)(iVar6 + 0x46) == 0x8c) {
          *piVar10 = iVar6;
          local_84 = local_88;
        }
      }
    }
    iVar5 = *(int *)(uVar3 + 0x30);
    if ((iVar5 == 0) || (*(short *)(iVar5 + 0x46) != 0x8e)) {
      iVar6 = 0;
      *(undefined *)((int)piVar10 + 10) = 4;
    }
    else {
      iVar6 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x24))(iVar5);
    }
    *(undefined *)((int)piVar10 + 0xd) = 1;
    cVar1 = *(char *)((int)piVar10 + 10);
    if (cVar1 == '\x03') {
      *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) & 0xfffe;
      if (*(char *)(piVar10 + 3) == '\0') {
        FUN_8008112c((double)FLOAT_803e6528,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar3,1,1,1,0,1,1,0);
        *(undefined *)((int)piVar10 + 10) = 4;
      }
      else {
        *(undefined *)((int)piVar10 + 10) = 5;
      }
    }
    else if (cVar1 < '\x03') {
      if (cVar1 != '\x01') {
        if (cVar1 < '\x01') {
          if (-1 < cVar1) {
            if ((iVar5 != 0) &&
               (iVar5 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x28))(iVar5), iVar5 == 0)) {
              if (*(char *)(iVar11 + 0x19) == '\0') {
                *(undefined *)((int)piVar10 + 10) = 2;
                *(undefined2 *)(piVar10 + 2) = 0x3c;
              }
              else {
                *(undefined *)((int)piVar10 + 10) = 2;
                *(undefined2 *)(piVar10 + 2) = 0;
              }
            }
            *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) =
                 *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) & 0xfffe;
          }
        }
        else {
          *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) =
               *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) | 1;
          iVar11 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x28))(iVar5);
          if ((iVar11 == 0) &&
             (iVar7 = ObjHits_GetPriorityHit(uVar3,(undefined4 *)0x0,(int *)0x0,(uint *)0x0), iVar7 != 0)) {
            in_r8 = 1;
            FUN_80017a28(uVar3,0xf,200,0,0,1);
            FUN_80006824(uVar3,0x36);
            *(char *)((int)piVar10 + 0xb) = *(char *)((int)piVar10 + 0xb) + '\x01';
            if (*(char *)((int)piVar10 + 0xb) == '\x04') {
              *(char *)(piVar10 + 3) = *(char *)(piVar10 + 3) + -1;
              *(undefined *)((int)piVar10 + 10) = 3;
              if (iVar5 != 0) {
                (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5);
              }
            }
            else if (*(char *)((int)piVar10 + 0xb) == '\b') {
              FUN_80006824(uVar3,0x3a);
              *(char *)(piVar10 + 3) = *(char *)(piVar10 + 3) + -1;
              *(undefined *)((int)piVar10 + 10) = 3;
              if (iVar5 != 0) {
                (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5);
              }
            }
          }
          if ((iVar5 != 0) && (iVar11 != 0)) {
            *(undefined *)((int)piVar10 + 10) = 3;
          }
          dVar13 = (double)(*(float *)(iVar4 + 0x18) - *(float *)(uVar3 + 0x18));
          dVar15 = (double)(*(float *)(iVar4 + 0x20) - *(float *)(uVar3 + 0x20));
          uVar8 = FUN_80017730();
          *(short *)(piVar10 + 1) = (short)((uVar8 & 0xffff) << 1);
          dVar13 = FUN_80293900((double)(float)(dVar13 * dVar13 + (double)(float)(dVar15 * dVar15)))
          ;
          iVar11 = FUN_80017730();
          *(short *)((int)piVar10 + 6) = (short)iVar11;
          if (*(short *)((int)piVar10 + 6) < 0x1f41) {
            if (*(short *)((int)piVar10 + 6) < -8000) {
              *(undefined2 *)((int)piVar10 + 6) = 0xe0c0;
            }
          }
          else {
            *(undefined2 *)((int)piVar10 + 6) = 8000;
          }
          *(ushort *)(piVar10 + 2) = *(short *)(piVar10 + 2) - (ushort)DAT_803dc070;
          if ((*(short *)(piVar10 + 2) < 0) && (uVar8 = FUN_80017ae8(), (uVar8 & 0xff) != 0)) {
            FUN_800068fc(uVar3,&local_78,&local_7c,&local_80);
            local_5c = FLOAT_803e6524;
            local_58 = FLOAT_803e6524;
            local_54[0] = FLOAT_803e6524;
            local_60 = FLOAT_803e6520;
            local_68[0] = *(ushort *)(piVar10 + 1);
            local_68[1] = 0;
            local_68[2] = 0;
            local_74 = FLOAT_803e6528;
            local_70 = FLOAT_803e652c;
            local_6c = FLOAT_803e6524;
            uVar12 = FUN_80017748(local_68,&local_74);
            puVar9 = FUN_80017aa4(0x18,0x113);
            *(float *)(puVar9 + 4) = local_78;
            *(float *)(puVar9 + 6) = local_7c;
            *(float *)(puVar9 + 8) = local_80;
            *(undefined *)(puVar9 + 2) = 2;
            *(undefined *)((int)puVar9 + 5) = 1;
            *(undefined *)(puVar9 + 3) = 0xff;
            *(undefined *)((int)puVar9 + 7) = 0xff;
            puVar9 = (undefined2 *)
                     FUN_80017ae4(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,
                                  puVar9,5,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
            iVar11 = *piVar10;
            dVar16 = (double)(*(float *)(iVar11 + 0x18) - *(float *)(uVar3 + 0x18));
            dVar15 = (double)(*(float *)(iVar11 + 0x1c) -
                             (*(float *)(uVar3 + 0x1c) - FLOAT_803e6530));
            dVar14 = (double)(*(float *)(iVar11 + 0x20) - *(float *)(uVar3 + 0x20));
            dVar13 = FUN_80293900((double)(float)(dVar14 * dVar14 +
                                                 (double)(float)(dVar16 * dVar16 +
                                                                (double)(float)(dVar15 * dVar15))));
            local_78 = FLOAT_803e6534 / (float)dVar13;
            *(float *)(puVar9 + 0x12) = (float)(dVar16 * (double)local_78);
            *(float *)(puVar9 + 0x14) = (float)(dVar15 * (double)local_78);
            *(float *)(puVar9 + 0x16) = (float)(dVar14 * (double)local_78);
            fVar2 = FLOAT_803e6538;
            *(float *)(puVar9 + 6) =
                 FLOAT_803e6538 * *(float *)(puVar9 + 0x12) + *(float *)(puVar9 + 6);
            *(float *)(puVar9 + 8) = fVar2 * *(float *)(puVar9 + 0x14) + *(float *)(puVar9 + 8);
            *(float *)(puVar9 + 10) = fVar2 * *(float *)(puVar9 + 0x16) + *(float *)(puVar9 + 10);
            iVar11 = FUN_80017730();
            *puVar9 = (short)iVar11;
            *(undefined4 *)(puVar9 + 0x7a) = 0x78;
            *(int *)(puVar9 + 0x7c) = *piVar10;
            FUN_800069bc();
            FUN_80006920((double)FLOAT_803e653c);
            FUN_80006824(uVar3,0x3c);
            *(char *)((int)piVar10 + 0xe) = *(char *)((int)piVar10 + 0xe) + '\x01';
            if (*(char *)((int)piVar10 + 0xe) == '\x03') {
              if (iVar6 < 3) {
                uVar8 = FUN_80017760(0,0x28);
                *(short *)(piVar10 + 2) = (short)uVar8 + 0x78;
              }
              else {
                uVar8 = FUN_80017760(0,0x28);
                *(short *)(piVar10 + 2) = (short)uVar8 + 0x50;
              }
              *(undefined *)((int)piVar10 + 0xe) = 0;
            }
            else if (iVar6 < 3) {
              *(undefined2 *)(piVar10 + 2) = 0x78;
            }
            else {
              *(undefined2 *)(piVar10 + 2) = 0x50;
            }
          }
        }
      }
    }
    else if (cVar1 == '\x05') {
      *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) & 0xfffe;
      if ((iVar5 != 0) &&
         (iVar5 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x28))(iVar5), iVar5 == 0)) {
        if (*(char *)(iVar11 + 0x19) == '\0') {
          if (2 < iVar6) {
            *(undefined *)((int)piVar10 + 10) = 2;
            *(undefined2 *)(piVar10 + 2) = 0x3c;
          }
        }
        else if (2 < iVar6) {
          *(undefined *)((int)piVar10 + 10) = 2;
          *(undefined2 *)(piVar10 + 2) = 0;
        }
      }
      local_60 = FLOAT_803e6540;
      local_68[3] = 0xc0a;
      FUN_800388b4(uVar3,0,&local_5c,&local_58,local_54,0);
      local_5c = local_5c - *(float *)(uVar3 + 0x18);
      local_58 = local_58 - *(float *)(uVar3 + 0x1c);
      local_54[0] = local_54[0] - *(float *)(uVar3 + 0x20);
      for (iVar11 = 0; iVar11 < (int)(uint)DAT_803dc070; iVar11 = iVar11 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(uVar3,0x7aa,local_68,2,0xffffffff,0);
      }
    }
    else if (cVar1 < '\x05') {
      local_60 = FLOAT_803e6540;
      local_68[3] = 0xc0a;
      FUN_800388b4(uVar3,0,&local_5c,&local_58,local_54,0);
      local_5c = local_5c - *(float *)(uVar3 + 0x18);
      local_58 = local_58 - *(float *)(uVar3 + 0x1c);
      local_54[0] = local_54[0] - *(float *)(uVar3 + 0x20);
      for (iVar11 = 0; iVar11 < (int)(uint)DAT_803dc070; iVar11 = iVar11 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(uVar3,0x7aa,local_68,2,0xffffffff,0);
      }
    }
    if (*(char *)(piVar10 + 3) == '\0') {
      dVar13 = (double)FUN_8001771c((float *)(iVar4 + 0x18),(float *)(uVar3 + 0x18));
      if ((double)FLOAT_803e6544 <= dVar13) {
        FUN_8000680c(uVar3,0x40);
      }
      else {
        FUN_80006824(uVar3,0x312);
      }
    }
  }
  FUN_80286888();
  return;
}
