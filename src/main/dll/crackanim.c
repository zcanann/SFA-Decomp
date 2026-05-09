#include "ghidra_import.h"
#include "main/dll/crackanim.h"

extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017a78();
extern int FUN_80017a98();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_8002fc3c();
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjMsg_Pop();
extern undefined4 FUN_80039520();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8017db40();
extern undefined4 FUN_8017de58();
extern int FUN_8017e15c();
extern int FUN_8017e3c0();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294d60();

extern u8 *Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void fn_80296AFC(u8 *player, int v);
extern void itemPickupDoParticleFx(int obj, f32 f1, int p3, int p4);

extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e44b8;
extern f32 lbl_803DC074;
extern f32 lbl_803E4460;
extern f32 lbl_803E4464;
extern f32 lbl_803E4468;
extern f32 lbl_803E446C;
extern f32 lbl_803E449C;
extern f32 lbl_803E44A0;
extern f32 lbl_803E44A4;
extern f32 lbl_803E44A8;
extern f32 lbl_803E44AC;
extern f32 lbl_803E44B0;

/*
 * --INFO--
 *
 * Function: appleontree_update
 * EN v1.0 Address: 0x8017E1A0
 * EN v1.0 Size: 2460b
 * EN v1.1 Address: 0x8017E6F8
 * EN v1.1 Size: 1988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void appleontree_update(int param_1)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  uint local_78;
  undefined auStack_74 [4];
  undefined8 local_70;
  longlong local_68;
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;

  puVar2 = (undefined2 *)param_1;
  iVar8 = *(int *)(puVar2 + 0x5c);
  iVar7 = *(int *)(puVar2 + 0x26);
  local_78 = 0;
  if ((*(byte *)(iVar8 + 0x5a) & 4) != 0) {
    while (iVar3 = ObjMsg_Pop((int)puVar2,&local_78,(uint *)0x0,(uint *)0x0), iVar3 != 0) {
      if (local_78 == 0x7000b) {
        fn_80296AFC(Obj_GetPlayerObject(), (int)*(u16 *)(iVar8 + 0x38));
        itemPickupDoParticleFx((int)puVar2, lbl_803E4460, 0xff, 0x28);
        Sfx_PlayFromObject((int)puVar2, 0x58);
        iVar3 = *(int *)(puVar2 + 0x5c);
        if ((puVar2[3] & 0x2000) == 0) {
          if (*(int *)(puVar2 + 0x2a) != 0) {
            ObjHits_DisableObject((int)puVar2);
          }
          *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 2;
        }
        else {
          Obj_FreeObject((int)puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) & 0xfb;
      }
    }
    if ((*(byte *)(iVar8 + 0x5a) & 4) != 0) goto switchD_8017e864_caseD_7;
  }
  if ((*(byte *)(iVar8 + 0x5a) & 2) == 0) {
    *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) + lbl_803DC074;
    fVar1 = *(float *)(iVar8 + 0xc);
    *(float *)(iVar8 + 0xc) = (float)((double)fVar1 + (double)lbl_803DC074);
    dVar11 = (double)*(float *)(iVar8 + 8);
    dVar13 = (double)(float)(dVar11 / (double)*(float *)(iVar8 + 4));
    switch(*(undefined *)(iVar8 + 0x3a)) {
    case 0:
      iVar3 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((iVar3 == 0) &&
         (((int)*(short *)(iVar7 + 0x26) == 0xffffffff ||
          (uVar5 = FUN_80017690((int)*(short *)(iVar7 + 0x26)), uVar5 == 0)))) {
        if (dVar13 <= (double)*(float *)(iVar8 + 0x10)) {
          iVar7 = *(int *)(puVar2 + 0x5c);
          *(float *)(puVar2 + 4) =
               *(float *)(*(int *)(puVar2 + 0x28) + 4) *
               (*(float *)(iVar7 + 8) / *(float *)(iVar7 + 4)) *
               (lbl_803E4460 / *(float *)(iVar7 + 0x10));
        }
        else {
          *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(*(int *)(puVar2 + 0x28) + 4);
          *(undefined *)(iVar8 + 0x3a) = 1;
        }
      }
      else {
        iVar8 = *(int *)(puVar2 + 0x5c);
        iVar7 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x55a,0,2,0xffffffff,0);
          iVar7 = iVar7 + 1;
        } while (iVar7 < 8);
        if (*(int *)(puVar2 + 0x2a) != 0) {
          ObjHits_DisableObject((int)puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) | 2;
        *(float *)(iVar8 + 8) = lbl_803DC074;
        *(undefined *)(iVar8 + 0x3a) = 5;
      }
      break;
    case 1:
      iVar3 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((iVar3 == 0) &&
         (((int)*(short *)(iVar7 + 0x26) == 0xffffffff ||
          (uVar5 = FUN_80017690((int)*(short *)(iVar7 + 0x26)), uVar5 == 0)))) {
        if (dVar13 <= (double)*(float *)(iVar8 + 0x14)) {
          iVar7 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_74);
          if (iVar7 == 0) {
            FUN_8002fc3c((double)lbl_803E44A0,(double)lbl_803DC074);
          }
          else {
            FUN_8002fc3c((double)lbl_803E449C,(double)lbl_803DC074);
          }
        }
        else {
          iVar7 = 0;
          do {
            (**(code **)(*DAT_803dd708 + 8))(puVar2,0x55a,0,2,0xffffffff,0);
            iVar7 = iVar7 + 1;
          } while (iVar7 < 8);
          *(undefined *)(iVar8 + 0x3a) = 2;
        }
      }
      else {
        iVar8 = *(int *)(puVar2 + 0x5c);
        iVar7 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x55a,0,2,0xffffffff,0);
          iVar7 = iVar7 + 1;
        } while (iVar7 < 8);
        if (*(int *)(puVar2 + 0x2a) != 0) {
          ObjHits_DisableObject((int)puVar2);
        }
        *(byte *)(iVar8 + 0x5a) = *(byte *)(iVar8 + 0x5a) | 2;
        *(float *)(iVar8 + 8) = lbl_803DC074;
        *(undefined *)(iVar8 + 0x3a) = 5;
      }
      break;
    case 2:
      if (dVar13 <= (double)*(float *)(iVar8 + 0x18)) {
        iVar3 = *(int *)(puVar2 + 0x5c);
        fVar1 = *(float *)(iVar3 + 8);
        dVar11 = (double)(-(*(float *)(iVar3 + 4) * *(float *)(iVar3 + 0x14) - fVar1) /
                         (*(float *)(iVar3 + 4) *
                         (*(float *)(iVar3 + 0x18) - *(float *)(iVar3 + 0x14))));
        fVar1 = fVar1 * fVar1 * fVar1 * fVar1;
        iVar8 = (int)((fVar1 * fVar1) / *(float *)(iVar3 + 0x54));
        local_70 = (double)(longlong)iVar8;
        piVar6 = (int *)FUN_80039520((int)puVar2,0);
        *piVar6 = 0x100 - iVar8;
        *(float *)(iVar3 + 0x24) = (float)((double)lbl_803E4468 * dVar11 + (double)lbl_803E4464)
        ;
        *(float *)(puVar2 + 4) = *(float *)(*(int *)(puVar2 + 0x28) + 4) * *(float *)(iVar3 + 0x24);
        FUN_80017a78((int)puVar2,1);
      }
      else {
        iVar3 = *(int *)(puVar2 + 0x5c);
        puVar4 = (undefined4 *)FUN_80039520((int)puVar2,0);
        *puVar4 = 0;
        *(float *)(iVar3 + 0x24) = lbl_803E4460;
        *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(*(int *)(puVar2 + 0x28) + 4);
        FUN_80017a78((int)puVar2,1);
        *(undefined *)(iVar8 + 0x3a) = 3;
      }
      iVar8 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((iVar8 != 0) ||
         (((int)*(short *)(iVar7 + 0x26) != 0xffffffff &&
          (uVar5 = FUN_80017690((int)*(short *)(iVar7 + 0x26)), uVar5 != 0)))) {
        FUN_8017db40((uint)puVar2,1);
      }
      break;
    case 3:
      *(float *)(iVar8 + 8) = (float)(dVar11 - (double)lbl_803DC074);
      if (dVar13 <= (double)*(float *)(iVar8 + 0x1c)) {
        iVar8 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
        if ((iVar8 != 0) ||
           (((int)*(short *)(iVar7 + 0x26) != 0xffffffff &&
            (uVar5 = FUN_80017690((int)*(short *)(iVar7 + 0x26)), uVar5 != 0)))) {
          FUN_8017db40((uint)puVar2,2);
        }
      }
      else {
        FUN_8017db40((uint)puVar2,0);
      }
      break;
    case 4:
      if (dVar13 <= (double)*(float *)(iVar8 + 0x20)) {
        iVar7 = 0;
        iVar3 = 0;
        dVar12 = (double)lbl_803E446C;
        do {
          double t = (double)*(float *)(iVar8 + 0xc);
          if (iVar7 != 0) break;
          dVar11 = (double)(float)(t *
                                  (double)(*(float *)(iVar8 + 0x40) + *(float *)(iVar8 + 0x3c)));
          dVar10 = (double)(float)(t * dVar11 +
                                  (double)(float)((double)*(float *)(iVar8 + 0x44) * t +
                                                 (double)*(float *)(iVar8 + 0x2c)));
          if ((double)*(float *)(iVar8 + 0x28) <= dVar12) {
            iVar7 = FUN_8017e15c(dVar10,puVar2,iVar8);
          }
          else {
            iVar7 = FUN_8017e3c0(dVar10,puVar2,iVar8);
          }
          iVar3 = iVar3 + 1;
        } while ((iVar3 == 100) || (iVar3 != 0x66));
        dVar12 = DOUBLE_803e44b8;
        dVar10 = (double)lbl_803E446C;
        if ((double)lbl_803E446C != (double)*(float *)(iVar8 + 0x30)) {
          dVar11 = (double)(*(float *)(iVar8 + 0xc) / *(float *)(iVar8 + 0x50));
          local_70 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 0x48) ^ 0x80000000);
          iVar7 = (int)((double)(float)(local_70 - DOUBLE_803e44b8) * dVar11);
          local_68 = (longlong)iVar7;
          *puVar2 = (short)iVar7;
          uStack_5c = (int)*(short *)(iVar8 + 0x4a) ^ 0x80000000;
          local_60 = 0x43300000;
          iVar7 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar12) * dVar11);
          local_58 = (longlong)iVar7;
          puVar2[1] = (short)iVar7;
          uStack_4c = (int)*(short *)(iVar8 + 0x4c) ^ 0x80000000;
          local_50 = 0x43300000;
          iVar7 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar12) * dVar11);
          local_48 = (longlong)iVar7;
          puVar2[2] = (short)iVar7;
          dVar10 = dVar12;
        }
        piVar6 = (int *)FUN_80039520((int)puVar2,0);
        local_48 = (longlong)(int)((double)lbl_803E44A4 * dVar13);
        *piVar6 = (int)((double)lbl_803E44A4 * dVar13);
        FUN_8017de58((uint)puVar2);
      }
      else {
        *(undefined *)(iVar8 + 0x3a) = 6;
        *(float *)(iVar8 + 8) = lbl_803DC074;
      }
      break;
    case 5:
      if ((double)lbl_803E44A8 < dVar11) {
        iVar7 = *(int *)(puVar2 + 0x5c);
        if ((puVar2[3] & 0x2000) == 0) {
          if (*(int *)(puVar2 + 0x2a) != 0) {
            ObjHits_DisableObject((int)puVar2);
          }
          *(byte *)(iVar7 + 0x5a) = *(byte *)(iVar7 + 0x5a) | 2;
        }
        else {
          Obj_FreeObject((int)puVar2);
        }
      }
      break;
    case 6:
      dVar13 = (double)lbl_803E44AC;
      if (dVar11 <= dVar13) {
        iVar7 = (int)((double)(float)((double)lbl_803E44B0 * dVar11) / dVar13);
        local_48 = (longlong)iVar7;
        *(char *)(puVar2 + 0x1b) = -1 - (char)iVar7;
        FUN_8017de58((uint)puVar2);
      }
      else {
        iVar7 = *(int *)(puVar2 + 0x5c);
        if ((puVar2[3] & 0x2000) == 0) {
          if (*(int *)(puVar2 + 0x2a) != 0) {
            ObjHits_DisableObject((int)puVar2);
          }
          *(byte *)(iVar7 + 0x5a) = *(byte *)(iVar7 + 0x5a) | 2;
        }
        else {
          Obj_FreeObject((int)puVar2);
        }
      }
    }
  }
switchD_8017e864_caseD_7:
  return;
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void fn_8017EC20(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_8017EC10(void) { return 0x8; }
int fn_8017EC18(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E3848;
extern void fn_8003B8F4(f32);
#pragma peephole off
void fn_8017EC24(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E3848); }
#pragma peephole reset
