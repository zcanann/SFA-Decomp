#include "ghidra_import.h"
#include "main/dll/DR/cannontargetControl.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8001777c();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80017ad0();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined8 ObjHits_EnableObject();
extern undefined4 ObjHits_RefreshObjectState();
extern undefined4 ObjHits_AddContactObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern int Obj_IsObjectAlive();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_8003b818();
extern int FUN_8005b398();
extern int FUN_80061a78();
extern undefined4 FUN_80061a80();
extern int FUN_800620e8();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8019f1dc();
extern undefined4 FUN_801a1230();
extern undefined4 FUN_801a136c();
extern undefined4 FUN_801a1654();
extern int FUN_8020a468();
extern undefined4 FUN_8020a470();
extern undefined4 FUN_8020a90c();
extern undefined4 FUN_8020a910();
extern uint FUN_8020a914();
extern byte FUN_8020a91c();
extern double SeekTwiceBeforeRead();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern byte FUN_80294c20();
extern double FUN_80294c6c();
extern uint FUN_80294ce8();
extern uint FUN_80294cf0();
extern uint FUN_80294db4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e4f90;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DCAE8;
extern f32 lbl_803DCAEC;
extern f32 lbl_803DCAF0;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F74;
extern f32 lbl_803E4FA4;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FAC;
extern f32 lbl_803E4FB0;
extern f32 lbl_803E4FB4;
extern f32 lbl_803E4FB8;
extern f32 lbl_803E4FBC;
extern f32 lbl_803E4FC0;
extern f32 lbl_803E4FC8;
extern f32 lbl_803E4FCC;
extern f32 lbl_803E4FD0;

extern f32 oneOverTimeDelta;
extern f32 lbl_803DBE84;
extern f32 lbl_803E42C0;
extern f32 lbl_803E4324;
extern f32 lbl_803E4328;
extern f32 lbl_803E432C;
extern f32 lbl_803E4330;
extern f32 lbl_803E4334;

extern int fn_80080150(void *p1);
extern int objHitDetectFn_80062e84(int p1, int p2, int p3);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void Vec3_ReflectAgainstNormal(void *normal, void *velocity, void *out);
extern f32 PSVECMag(f32 *v);
extern int gunpowderbarrel_setPlayerHeldState(int p1, int p2);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void objRenderFn_8003b8f4(f32 alpha);
extern f32 lbl_803E4348;

/*
 * --INFO--
 *
 * Function: gunpowderbarrel_hitDetect
 * EN v1.0 Address: 0x801A1A60
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801A1A78
 * EN v1.1 Size: 984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void gunpowderbarrel_hitDetect(int param_1)
{
    int p_b8;
    f32 sp10[3];
    f32 sp1c[3];
    f32 collision_buf[26];

    p_b8 = *(int *)(param_1 + 0xb8);

    if (Obj_IsObjectAlive(*(int *)(p_b8 + 0x10)) == 0) {
        if (*(int *)(p_b8 + 0x10) != 0) {
            ObjLink_DetachChild(param_1);
            *(int *)(p_b8 + 0x10) = 0;
        }
    }

    if (*(u8 *)(p_b8 + 0x17) != 0) {
        return;
    }

    if (fn_80080150((void *)(p_b8 + 0x18)) != 0) {
        return;
    }
    if (fn_80080150((void *)(p_b8 + 0x1c)) != 0) {
        return;
    }

    if (*(int *)(p_b8 + 0xc) != 0) {
        objHitDetectFn_80062e84(param_1, *(int *)(p_b8 + 0xc), 1);
        *(int *)(p_b8 + 0xc) = 0;
    }

    if ((*(u8 *)(p_b8 + 0x4a) >> 7 & 1) != 0) {
        sp1c[0] = *(f32 *)(param_1 + 0xc) - *(f32 *)(param_1 + 0x80);
        sp1c[1] = *(f32 *)(param_1 + 0x10) - *(f32 *)(param_1 + 0x84);
        sp1c[2] = *(f32 *)(param_1 + 0x14) - *(f32 *)(param_1 + 0x88);
        {
            f32 inv = lbl_803E4324 * oneOverTimeDelta;
            sp1c[0] = sp1c[0] * inv;
            sp1c[1] = sp1c[1] * inv;
            sp1c[2] = sp1c[2] * inv;
        }
        *(f32 *)(p_b8 + 0x20) = sp1c[0] + *(f32 *)(p_b8 + 0x20);
        *(f32 *)(p_b8 + 0x24) = sp1c[1] + *(f32 *)(p_b8 + 0x24);
        *(f32 *)(p_b8 + 0x28) = sp1c[2] + *(f32 *)(p_b8 + 0x28);
        sp1c[1] = lbl_803E42C0;
        *(f32 *)(p_b8 + 0x20) = lbl_803E4328 * *(f32 *)(p_b8 + 0x20);
        *(f32 *)(p_b8 + 0x24) = lbl_803E4328 * *(f32 *)(p_b8 + 0x24);
        *(f32 *)(p_b8 + 0x28) = lbl_803E4328 * *(f32 *)(p_b8 + 0x28);
        *(f32 *)(p_b8 + 0x24) = sp1c[1];
        *(u8 *)(p_b8 + 0x49) = (u8)(*(u8 *)(p_b8 + 0x49) | 1);
    }

    if (*(u8 *)(p_b8 + 0x15) != 0) {
        goto copy_end;
    }

    if (objBboxFn_800640cc(param_1 + 0x80, param_1 + 0xc, lbl_803E432C, 1,
                    (int)&collision_buf[0], param_1, 8, -1, 0xff, 0) == 0) {
        goto copy_end;
    }

    if ((s8)*((u8 *)&collision_buf[0] + 0x51) == 0x14) {
        *(u8 *)(p_b8 + 0x16) = 4;
    }

    if ((*(u8 *)(p_b8 + 0x4a) >> 7 & 1) != 0 &&
        (s8)*((u8 *)&collision_buf[0] + 0x51) == 3) {
        gunpowderbarrel_setPlayerHeldState(param_1, 0);
        ObjGroup_RemoveObject(param_1, 0x16);
        goto copy_end;
    }

    sp10[0] = *((f32 *)&collision_buf[0] + 7);
    sp10[1] = *((f32 *)&collision_buf[0] + 8);
    sp10[2] = *((f32 *)&collision_buf[0] + 9);
    Vec3_ReflectAgainstNormal(sp10, (void *)(param_1 + 0x24), (void *)(param_1 + 0x24));
    Vec3_ReflectAgainstNormal(sp10, (void *)(p_b8 + 0x20), (void *)(p_b8 + 0x20));

    *(f32 *)(param_1 + 0x24) = lbl_803E4330 * *(f32 *)(param_1 + 0x24);
    *(f32 *)(param_1 + 0x28) = lbl_803E4330 * *(f32 *)(param_1 + 0x28);
    *(f32 *)(param_1 + 0x2c) = lbl_803E4330 * *(f32 *)(param_1 + 0x2c);
    *(f32 *)(p_b8 + 0x20) = lbl_803E4330 * *(f32 *)(p_b8 + 0x20);
    *(f32 *)(p_b8 + 0x24) = lbl_803E4330 * *(f32 *)(p_b8 + 0x24);
    *(f32 *)(p_b8 + 0x28) = lbl_803E4330 * *(f32 *)(p_b8 + 0x28);
    /* mark sp1c live: target stores into sp+0x1c..0x24 the dx/dy/dz */
    (void)sp1c;

    if (*(f32 *)(p_b8 + 0x54) > lbl_803E4334) {
        if (PSVECMag((f32 *)(p_b8 + 0x20)) > lbl_803DBE84) {
            Sfx_PlayFromObject(param_1, 0x446);
        }
        *(f32 *)(p_b8 + 0x54) = lbl_803E42C0;
    }

copy_end:
    *(f32 *)(param_1 + 0x80) = *(f32 *)(param_1 + 0xc);
    *(f32 *)(param_1 + 0x84) = *(f32 *)(param_1 + 0x10);
    *(f32 *)(param_1 + 0x88) = *(f32 *)(param_1 + 0x14);
    return;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_801a1df8
 * EN v1.0 Address: 0x801A1DF8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801A1E50
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1df8(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd740 + 0x10))();
  if (((*(int *)(iVar2 + 0x10) != 0) && (param_2 == 0)) &&
     (iVar1 = Obj_IsObjectAlive(*(int *)(iVar2 + 0x10)), iVar1 != 0)) {
    ObjLink_DetachChild(param_1,*(int *)(iVar2 + 0x10));
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  ObjGroup_RemoveObject(param_1,0x19);
  ObjGroup_RemoveObject(param_1,0x16);
  if (*(char *)(iVar2 + 0x17) != '\0') {
    (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a1ec4
 * EN v1.0 Address: 0x801A1EC4
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801A1F14
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1ec4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar2 + 0xb8);
  if ((*(char *)(iVar3 + 0x17) == '\0') && ((*(byte *)(iVar3 + 0x4a) >> 5 & 1) == 0)) {
    if (*(char *)(iVar3 + 0x15) != '\0') {
      *(undefined2 *)(iVar2 + 4) = 0;
      *(undefined2 *)(iVar2 + 2) = 0;
    }
    iVar1 = (**(code **)(*DAT_803dd740 + 0xc))(iVar2,(int)(char)param_6);
    if ((iVar1 != 0) || ((char)param_6 == -1)) {
      FUN_8003b818(iVar2);
    }
    iVar2 = *(int *)(iVar3 + 0x10);
    if (iVar2 != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x10))
                (iVar2,(int)uVar4,param_3,param_4,param_5,param_6);
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: blasted_getExtraSize
 * EN v1.0 Address: 0x801A24A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801A2690
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int blasted_getExtraSize(void)
{
  return 0x14;
}

/*
 * --INFO--
 *
 * Function: blasted_getObjectTypeId
 * EN v1.0 Address: 0x801A24B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801A2698
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int blasted_getObjectTypeId(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: blasted_free
 * EN v1.0 Address: 0x801A24B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A26A0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void blasted_free(void)
{
}

/*
 * --INFO--
 *
 * Function: blasted_hitDetect
 * EN v1.0 Address: 0x801A24FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A26E4
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void blasted_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void blasted_render(int *obj, int p2, int p3, int p4, int p5, s8 visible)
{
  int *state = *(int **)((char *)obj + 0xb8);
  if (visible != 0 && state[3] == 0) {
    objRenderFn_8003b8f4(lbl_803E4348);
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801a1fb8
 * EN v1.0 Address: 0x801A1FB8
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801A2014
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1fb8(int *param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  float local_80;
  undefined4 local_7c;
  undefined4 local_78;
  float local_74;
  float local_70;
  float local_6c;
  int aiStack_68 [7];
  float local_4c;
  undefined4 local_48;
  undefined4 local_44;
  char local_17;
  
  iVar6 = param_1[0x2e];
  iVar4 = Obj_IsObjectAlive(*(int *)(iVar6 + 0x10));
  if ((iVar4 == 0) && (*(int *)(iVar6 + 0x10) != 0)) {
    ObjLink_DetachChild((int)param_1,*(int *)(iVar6 + 0x10));
    *(undefined4 *)(iVar6 + 0x10) = 0;
  }
  if (((*(char *)(iVar6 + 0x17) == '\0') &&
      (uVar5 = FUN_8007f6c8((float *)(iVar6 + 0x18)), uVar5 == 0)) &&
     (uVar5 = FUN_8007f6c8((float *)(iVar6 + 0x1c)), uVar5 == 0)) {
    if (*(short **)(iVar6 + 0xc) != (short *)0x0) {
      FUN_80061a80((short *)param_1,*(short **)(iVar6 + 0xc),1);
      *(undefined4 *)(iVar6 + 0xc) = 0;
    }
    if (*(char *)(iVar6 + 0x4a) < '\0') {
      fVar1 = (float)param_1[4];
      fVar2 = (float)param_1[0x21];
      fVar3 = lbl_803E4FBC * lbl_803DC078;
      local_74 = ((float)param_1[3] - (float)param_1[0x20]) * fVar3;
      local_6c = ((float)param_1[5] - (float)param_1[0x22]) * fVar3;
      *(float *)(iVar6 + 0x20) = local_74 + *(float *)(iVar6 + 0x20);
      *(float *)(iVar6 + 0x24) = (fVar1 - fVar2) * fVar3 + *(float *)(iVar6 + 0x24);
      *(float *)(iVar6 + 0x28) = local_6c + *(float *)(iVar6 + 0x28);
      fVar2 = lbl_803E4FC0;
      fVar1 = lbl_803E4F58;
      local_70 = lbl_803E4F58;
      *(float *)(iVar6 + 0x20) = lbl_803E4FC0 * *(float *)(iVar6 + 0x20);
      *(float *)(iVar6 + 0x24) = fVar2 * *(float *)(iVar6 + 0x24);
      *(float *)(iVar6 + 0x28) = fVar2 * *(float *)(iVar6 + 0x28);
      *(float *)(iVar6 + 0x24) = fVar1;
      *(byte *)(iVar6 + 0x49) = *(byte *)(iVar6 + 0x49) | 1;
    }
    if ((*(char *)(iVar6 + 0x15) == '\0') &&
       (iVar4 = FUN_800620e8(param_1 + 0x20,param_1 + 3,(float *)0x1,aiStack_68,param_1,8,0xffffffff
                             ,0xff,0), iVar4 != 0)) {
      if (local_17 == '\x14') {
        *(undefined *)(iVar6 + 0x16) = 4;
      }
      if ((*(char *)(iVar6 + 0x4a) < '\0') && (local_17 == '\x03')) {
        FUN_801a1230((int)param_1,'\0');
        ObjGroup_RemoveObject((int)param_1,0x16);
      }
      else {
        local_80 = local_4c;
        local_7c = local_48;
        local_78 = local_44;
        FUN_8001777c(&local_80,(float *)(param_1 + 9),(float *)(param_1 + 9));
        FUN_8001777c(&local_80,(float *)(iVar6 + 0x20),(float *)(iVar6 + 0x20));
        fVar1 = lbl_803E4FC8;
        param_1[9] = (int)(lbl_803E4FC8 * (float)param_1[9]);
        param_1[10] = (int)(fVar1 * (float)param_1[10]);
        param_1[0xb] = (int)(fVar1 * (float)param_1[0xb]);
        *(float *)(iVar6 + 0x20) = fVar1 * *(float *)(iVar6 + 0x20);
        *(float *)(iVar6 + 0x24) = fVar1 * *(float *)(iVar6 + 0x24);
        *(float *)(iVar6 + 0x28) = fVar1 * *(float *)(iVar6 + 0x28);
        if (lbl_803E4FCC < *(float *)(iVar6 + 0x54)) {
          dVar7 = SeekTwiceBeforeRead((float *)(iVar6 + 0x20));
          if ((double)lbl_803DCAEC < dVar7) {
            FUN_80006824((uint)param_1,0x446);
          }
          *(float *)(iVar6 + 0x54) = lbl_803E4F58;
        }
      }
    }
    param_1[0x20] = param_1[3];
    param_1[0x21] = param_1[4];
    param_1[0x22] = param_1[5];
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a2350
 * EN v1.0 Address: 0x801A2350
 * EN v1.0 Size: 2244b
 * EN v1.1 Address: 0x801A22FC
 * EN v1.1 Size: 2208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a2350(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  uint uVar2;
  short *psVar3;
  uint uVar4;
  byte bVar8;
  int iVar5;
  int *piVar6;
  int iVar7;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  double dVar14;
  int local_58;
  uint local_54;
  uint local_50;
  float local_4c [2];
  uint uStack_44;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  uVar2 = FUN_80286838();
  iVar12 = *(int *)(uVar2 + 0xb8);
  psVar3 = (short *)FUN_80017a98();
  iVar10 = *(int *)(uVar2 + 0x4c);
  if (*(float *)(iVar12 + 0x54) <= lbl_803E4FCC) {
    *(float *)(iVar12 + 0x54) = *(float *)(iVar12 + 0x54) + lbl_803DC074;
  }
  uVar4 = FUN_8007f6c8((float *)(iVar12 + 0x18));
  if (uVar4 == 0) {
    uVar4 = FUN_8007f6c8((float *)(iVar12 + 0x1c));
    if (uVar4 == 0) {
      if ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0) {
        if (((*(byte *)(iVar12 + 0x4a) >> 2 & 1) == 0) ||
           (bVar8 = FUN_80294c20((int)psVar3), bVar8 != 0)) {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) & 0xef;
        }
        else {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 0x10;
        }
      }
      if (*(int *)(uVar2 + 200) == 0) {
        local_4c[0] = lbl_803E4FD0;
        iVar5 = ObjGroup_FindNearestObject(0x4c,uVar2,local_4c);
        *(int *)(iVar12 + 0x10) = iVar5;
        if (((iVar5 != 0) && (uVar4 = FUN_8020a914(*(int *)(iVar12 + 0x10)), uVar4 != 0)) &&
           (*(int *)(*(int *)(iVar12 + 0x10) + 0xc4) == 0)) {
          ObjLink_AttachChild(uVar2,*(int *)(iVar12 + 0x10),0);
        }
      }
      else {
        iVar5 = Obj_IsObjectAlive(*(int *)(iVar12 + 0x10));
        if ((iVar5 == 0) && (*(int *)(iVar12 + 0x10) != 0)) {
          ObjLink_DetachChild(uVar2,*(int *)(iVar12 + 0x10));
          *(undefined4 *)(iVar12 + 0x10) = 0;
        }
      }
      local_54 = 0;
      local_50 = 0;
      while (iVar5 = ObjMsg_Pop(uVar2,&local_54,(uint *)0x0,&local_50), iVar5 != 0) {
        if (local_54 == 0x10) {
          FUN_801a1230(uVar2,'\0');
          if (local_50 != 0) {
            ObjGroup_AddObject(uVar2,0x16);
          }
        }
        else if (((int)local_54 < 0x10) && (0xe < (int)local_54)) {
          FUN_801a1230(uVar2,'\x01');
        }
      }
      if ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0) {
        *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) & 0xf7;
      }
      else {
        *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
      }
      if (*(char *)(iVar12 + 0x17) == '\0') {
        if (*(char *)(iVar12 + 0x15) == '\0') {
          if ((((*(byte *)(iVar12 + 0x48) >> 6 & 1) != 0) &&
              ((*(byte *)(iVar12 + 0x4a) >> 4 & 1) != 0)) && ((*(byte *)(iVar12 + 0x49) & 2) == 0))
          {
            FUN_800e8630(uVar2);
          }
        }
        else {
          uVar4 = FUN_80294db4((int)psVar3);
          if ((uVar4 & 0x4000) == 0) {
            FUN_8011e868(4);
          }
          else {
            FUN_8011e868(5);
          }
        }
        if (((((*(byte *)(iVar12 + 0x49) & 2) == 0) && ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0))
            && (iVar10 = (**(code **)(*DAT_803dd740 + 8))(uVar2,iVar12), iVar10 != 0)) &&
           ((uVar13 = extraout_f1, (*(byte *)(iVar12 + 0x4a) >> 2 & 1) == 0 ||
            (bVar8 = FUN_80294c20((int)psVar3), bVar8 != 0)))) {
          *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) | 1;
          if (*(char *)(iVar12 + 0x15) == '\0') {
            if (*(int *)(iVar12 + 0x10) != 0) {
              FUN_8020a910(*(int *)(iVar12 + 0x10));
            }
            uVar13 = ObjGroup_RemoveObject(uVar2,0x16);
          }
          *(undefined *)(iVar12 + 0x15) = 1;
          *(byte *)(iVar12 + 0x4a) = *(byte *)(iVar12 + 0x4a) & 0xbf | 0x40;
          *(short *)(iVar12 + 0x50) = *psVar3;
          FUN_801a1654(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        else {
          uVar13 = ObjHits_EnableObject(uVar2);
          FUN_801a1654(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          *(undefined *)(uVar2 + 0x36) = 0xff;
          if (*(char *)(iVar12 + 0x15) != '\0') {
            *(undefined *)(iVar12 + 0x15) = 0;
            uVar4 = FUN_80294cf0((int)psVar3);
            if (uVar4 == 0) {
              uVar4 = FUN_80294ce8((int)psVar3);
              if (uVar4 == 0) {
                dVar14 = FUN_80294c6c((int)psVar3);
                if ((double)lbl_803E4F58 == dVar14) {
                  ObjHits_SyncObjectPositionIfDirty(uVar2);
                  FUN_8019f1dc();
                }
                else if (*(char *)(iVar12 + 0x17) == '\0') {
                  local_30 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_80293f90();
                  *(float *)(iVar12 + 0x20) = (float)dVar14;
                  *(float *)(uVar2 + 0x24) = (float)dVar14;
                  fVar1 = lbl_803E4F58;
                  *(float *)(iVar12 + 0x24) = lbl_803E4F58;
                  *(float *)(uVar2 + 0x28) = fVar1;
                  local_38 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_80294964();
                  *(float *)(iVar12 + 0x28) = (float)dVar14;
                  *(float *)(uVar2 + 0x2c) = (float)dVar14;
                  local_40 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_80293f90();
                  *(float *)(uVar2 + 0xc) =
                       (float)((double)lbl_803DCAE8 * -dVar14 + (double)*(float *)(uVar2 + 0xc));
                  uStack_44 = (int)*psVar3 ^ 0x80000000;
                  local_4c[1] = 176.0;
                  dVar14 = (double)FUN_80294964();
                  *(float *)(uVar2 + 0x14) =
                       (float)((double)lbl_803DCAE8 * -dVar14 + (double)*(float *)(uVar2 + 0x14));
                  ObjGroup_AddObject(uVar2,0x16);
                }
              }
              else {
                ObjHits_MarkObjectPositionDirty(uVar2);
                FUN_8019f1dc();
              }
            }
            else {
              ObjHits_SyncObjectPositionIfDirty(uVar2);
            }
            ObjGroup_AddObject(uVar2,0x16);
          }
          gunpowderbarrel_hitDetect(uVar2);
        }
        if (*(char *)(iVar12 + 0x4a) < '\0') {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
          if (((*(byte *)(iVar12 + 0x4a) >> 6 & 1) != 0) && ((char)*(byte *)(iVar12 + 0x4a) < '\0'))
          {
            *(undefined4 *)(iVar12 + 0x20) = *(undefined4 *)(uVar2 + 0x24);
            *(undefined4 *)(iVar12 + 0x24) = *(undefined4 *)(uVar2 + 0x28);
            *(undefined4 *)(iVar12 + 0x28) = *(undefined4 *)(uVar2 + 0x2c);
            *(float *)(iVar12 + 0x24) = lbl_803E4F58;
            *(byte *)(iVar12 + 0x4a) = *(byte *)(iVar12 + 0x4a) & 0xbf;
          }
        }
        if ((*(int *)(iVar12 + 0x10) != 0) &&
           (bVar8 = FUN_8020a91c(*(int *)(iVar12 + 0x10)), bVar8 != 0)) {
          *(undefined *)(iVar12 + 0x16) = 10;
        }
      }
      else {
        *(char *)(iVar12 + 0x17) = *(char *)(iVar12 + 0x17) + DAT_803dc070;
        uStack_44 = (uint)*(byte *)(iVar12 + 0x17);
        local_4c[1] = 176.0;
        *(float *)(iVar12 + 0x2c) =
             *(float *)(iVar12 + 0x34) *
             (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4f90) + lbl_803E4F74;
        fVar1 = *(float *)(iVar12 + 0x2c);
        local_40 = (longlong)(int)fVar1;
        local_38 = (longlong)(int)(-fVar1 * lbl_803E4FC0);
        local_30 = (longlong)(int)(fVar1 * lbl_803E4FC0);
        ObjHitbox_SetCapsuleBounds(uVar2,(short)(int)fVar1,(short)(int)(-fVar1 * lbl_803E4FC0),
                     (short)(int)(fVar1 * lbl_803E4FC0));
        if (*(int *)(iVar12 + 0x10) != 0) {
          FUN_8020a90c(*(int *)(iVar12 + 0x10));
        }
        if (0x14 < *(byte *)(iVar12 + 0x17)) {
          if (*(char *)(iVar12 + 0x4a) < '\0') {
            FUN_801a1230(uVar2,'\0');
          }
          iVar5 = 0;
          if (*(short *)(iVar10 + 0x1a) == 0) {
            iVar5 = ObjGroup_FindNearestObject(0x3a,uVar2,(float *)0x0);
          }
          else {
            piVar6 = ObjGroup_GetObjects(0x3a,&local_58);
            piVar9 = piVar6;
            for (iVar11 = 0; iVar11 < local_58; iVar11 = iVar11 + 1) {
              iVar7 = FUN_8020a468(*piVar9);
              if (*(short *)(iVar10 + 0x1a) == iVar7) {
                iVar5 = piVar6[iVar11];
                break;
              }
              piVar9 = piVar9 + 1;
            }
          }
          if (iVar5 == 0) {
            FUN_80017ad0(uVar2);
            ObjHits_DisableObject(uVar2);
            *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            FUN_8007f718((float *)(iVar12 + 0x18),0x3c);
          }
          else {
            FUN_800033a8(iVar12 + 0x20,0,0xc);
            FUN_800033a8(uVar2 + 0x24,0,0xc);
            *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) & 0xfd;
            ObjHits_RefreshObjectState(uVar2);
            if (*(char *)(iVar12 + 0x48) < '\0') {
              FUN_8007f718((float *)(iVar12 + 0x18),0x3c);
              FUN_8007f6e4((undefined4 *)(iVar12 + 0x1c));
              FUN_8007f718((float *)(iVar12 + 0x1c),0x5a);
              FUN_8020a470(iVar5,uVar2,0x46);
              ObjHits_ClearHitVolumes(uVar2);
              ObjHits_DisableObject(uVar2);
              *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            }
            else {
              FUN_80017ad0(uVar2);
              ObjHits_DisableObject(uVar2);
              *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            }
          }
        }
      }
    }
    else {
      *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
      FUN_8007f764((float *)(iVar12 + 0x1c));
      FUN_800033a8(iVar12 + 0x20,0,0xc);
      FUN_800033a8(uVar2 + 0x24,0,0xc);
    }
  }
  else {
    *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    iVar10 = FUN_8007f764((float *)(iVar12 + 0x18));
    if (iVar10 != 0) {
      *(undefined *)(iVar12 + 0x17) = 0;
      *(undefined *)(iVar12 + 0x16) = 0;
      *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) | 1;
      *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) & 0xbfff;
      ObjHits_ClearHitVolumes(uVar2);
      ObjHitbox_SetCapsuleBounds(uVar2,8,-2,0x19);
      ObjHits_EnableObject(uVar2);
      ObjHits_SyncObjectPositionIfDirty(uVar2);
      gunpowderbarrel_hitDetect(uVar2);
      FUN_801a1230(uVar2,'\0');
    }
  }
  FUN_80286884();
  return;
}

extern int *lbl_803DCAC0; /* carryable-object interface singleton */
extern void ObjMsg_AllocQueue(int obj, int capacity);
extern void storeZeroToFloatParam(void *p);

typedef struct {
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 b3 : 1;
    u8 b2 : 1;
    u8 b1 : 1;
    u8 b0 : 1;
} BarrelBits;

/* EN v1.0 0x801A25E8  size: 464b  Gunpowder-barrel setup: registers with the
 * carryable interface and obj groups, zeroes the roll/contact state, seeds
 * the hit radius from the model's bound halfword, and latches the
 * indestructible bit for the cannon-range variant (type 0x754). */
#pragma scheduling off
#pragma peephole off
void gunpowderbarrel_init(int obj, u8 *def)
{
    int st = *(int *)(obj + 0xb8);

    *(u8 *)(st + 0x7) |= 2;
    (*(void (**)(int, int, int))((char *)*lbl_803DCAC0 + 0x4))(obj, st, 5);
    ObjGroup_AddObject(obj, 0x19);
    ObjGroup_AddObject(obj, 0x16);
    ObjMsg_AllocQueue(obj, 8);
    *(int *)(obj + 0xf8) = 0;
    *(s16 *)(st + 0x44) = 0;
    *(s16 *)(st + 0x46) = 0;
    *(u8 *)(st + 0x15) = 0;
    *(s16 *)(st + 0x3c) = 0;
    *(u8 *)(st + 0x16) = 0;
    *(u8 *)(st + 0x17) = 0;
    *(u8 *)(st + 0x3e) = 0;
    *(int *)(st + 0x40) = 0;
    *(f32 *)(st + 0x30) = lbl_803E42C0;
    *(u8 *)(st + 0x49) = 0;
    storeZeroToFloatParam((void *)(st + 0x18));
    storeZeroToFloatParam((void *)(st + 0x1c));
    *(u8 *)(st + 0x49) |= 1;
    {
        u8 v;
        if ((s8)def[0x19] >= 1) {
            v = 0;
        } else {
            v = 1;
        }
        ((BarrelBits *)(st + 0x48))->b7 = v;
        if (*(s16 *)(def + 0x1c) == 0) {
            v = 0;
        } else {
            v = 1;
        }
        ((BarrelBits *)(st + 0x48))->b6 = v;
    }
    ObjHits_EnableObject(obj);
    *(f32 *)(st + 0x2c) = (f32)*(s16 *)(*(int *)(obj + 0x54) + 0x5a);
    ((BarrelBits *)(st + 0x4a))->b5 = 0;
    *(f32 *)(st + 0x38) = lbl_803E42C0;
    *(int *)(st + 0x10) = 0;
    (*(void (**)(int, int))((char *)*lbl_803DCAC0 + 0x2c))(st, 1);
    if (*(void **)(obj + 0x54) != NULL) {
        *(s16 *)(*(int *)(obj + 0x54) + 0xb2) = 1;
    }
    if (*(s16 *)(obj + 0x46) == 0x754) {
        ((BarrelBits *)(st + 0x4a))->b1 = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern u8 *mapGetBlock(int idx);
extern u8 *mapBlockFn_800606ec(void *block, int idx);
extern int mapBlockFn_80060678(void *entry);
extern u8 *fn_8006070C(void *block, int idx);

/* EN v1.0 0x801A27B8  size: 280b  Flags every trigger/volume in the map
 * block under the object that carries the given event id: sets bits 0..1
 * on matching block entries and bit 1 on matching group records. Returns 0
 * when the block is missing or not trigger-enabled. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int fn_801A27B8(int obj, int id)
{
    u8 *block;

    block = mapGetBlock(objPosToMapBlockIdx(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                                            *(f32 *)(obj + 0x14)));
    if (block == NULL || (*(u16 *)(block + 4) & 0x8) == 0) {
        return 0;
    }
    {
        int j;
        int i;
        for (i = 0; i < *(u16 *)(block + 0x9a); i++) {
            u8 *e = mapBlockFn_800606ec(block, i);
            if (id == mapBlockFn_80060678(e)) {
                *(int *)(e + 0x10) |= 3;
            }
        }
        for (j = 0; j < *(u8 *)(block + 0xa2); j++) {
            u8 *g = fn_8006070C(block, j);
            int k;
            u8 *p;
            k = 0;
            p = g;
            for (; k < *(u8 *)(g + 0x41); k++) {
                if (*(u8 *)(p + 0x29) == id) {
                    *(int *)(g + 0x3c) |= 2;
                }
                p += 8;
            }
        }
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern int  GameBit_Get(int bit);
extern void GameBit_Set(int bit, int val);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int  lbl_803DDB18;

/* EN v1.0 0x801A2928  size: 464b  Blasted-target update: once the target's
 * GameBit is latched, fires the map trigger; otherwise scans the model's
 * hit nodes for newly-destroyed (state 5) pieces, records each unique piece,
 * advances the damage model index, and on the final piece latches the
 * GameBit, fires the trigger, and swaps to the destroyed model. */
#pragma scheduling off
#pragma peephole off
void blasted_update(int obj)
{
    int def = *(int *)(obj + 0x4c);
    int st = *(int *)(obj + 0xb8);
    s16 total = *(s16 *)(def + 0x1a);

    if (*(int *)(st + 0xc) != 0) {
        return;
    }
    if ((u32)GameBit_Get(*(s16 *)(def + 0x1e)) != 0) {
        *(int *)(st + 0xc) = fn_801A27B8(obj, *(s16 *)(def + 0x1c));
        return;
    }
    {
        int i;
        for (i = 0; i < (s8)*(u8 *)(*(int *)(obj + 0x54) + 0x71); i++) {
            u32 v;
            s8 m;
            int found;
            m = *(u8 *)(*(int *)(obj + 0x54) + i + 0x75);
            v = *(u32 *)(*(int *)(obj + 0x54) + i * 4 + 0x7c);
            found = 0;
            if (m != 5) {
                continue;
            }
            if (total == 0) {
                GameBit_Set(*(s16 *)(def + 0x1e), 1);
                return;
            }
            if (m == 5) {
                int k = 0;
                int cnt = *(u8 *)(st + 0x11);
                while (k != cnt) {
                    if (v == *(u32 *)(st + k++ * 4)) {
                        k = cnt;
                        found = 1;
                    }
                }
            }
            if (found == 0) {
                *(u32 *)(st + *(u8 *)(st + 0x11) * 4) = v;
                GameBit_Set(*(u8 *)(st + 0x11) + 0x2de, 0);
                GameBit_Set(*(u8 *)(st + 0x11) + 0x2df, 1);
                if (*(s16 *)(def + 0x20) != -1) {
                    GameBit_Set(*(s16 *)(def + 0x20), *(u8 *)(st + 0x11) + 1);
                }
                lbl_803DDB18 = 0x12c;
                if (*(u8 *)(st + 0x11) + 1 > total) {
                    int n;
                    int lim;
                    lim = total + 1;
                    for (n = 0; n < lim; n++) {
                        GameBit_Set(n + 0x2de, 0);
                    }
                    GameBit_Set(*(s16 *)(def + 0x1e), 1);
                    fn_801A27B8(obj, *(s16 *)(def + 0x1c));
                    Obj_SetActiveModelIndex(obj, 2);
                    *(int *)(st + 0xc) = 1;
                } else {
                    *(u8 *)(st + 0x11) = *(u8 *)(st + 0x11) + 1;
                    Obj_SetActiveModelIndex(obj, *(u8 *)(st + 0x11));
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int  timerCountDown(void *p);
extern void s16toFloat(void *p, int v);
extern void memset(void *p, int c, int n);
extern int  playerIsDisguised(u8 *player);
extern int  timer_isEffectMode(int obj);
extern void timer_clearManualFlags(int obj);
extern void timer_forceStart(int obj);
extern int  timer_hasExpired(int obj);
extern int  barrelgener_getLinkId(int gen);
extern void barrelgener_queueObjectRelease(int gen, int obj, int code);
extern void objRemoveFromListFn_8002ce88(int obj);
extern u32  playerGetStateFlag310(u8 *player);
extern void setAButtonIcon(int kind);
extern void saveGame_saveObjectPos(int obj);
extern int  fn_802966B4(u8 *player);
extern int  fn_8029669C(u8 *player);
extern f32  fn_80296214(u8 *player);
extern f32  fn_80293E80(f32 x);
extern f32  sin(f32 x);
extern void gunpowderbarrel_updatePhysics(int obj);
extern void fn_801A1230(int obj);
extern u8  *Obj_GetPlayerObject(void);
extern u8   framesThisStep;
extern f32  timeDelta;
extern f32  lbl_803E4338;
extern f32  lbl_803E42DC;
extern f32  lbl_803E433C;
extern f32  lbl_803E4340;
extern f32  lbl_803DBE80;

/* EN v1.0 0x801A1D48  size: 2208b  Gunpowder-barrel per-frame driver: runs
 * the fuse/respawn timers, manages the cannon attach link, drains the
 * held/released message queue, grows the hitbox while the fuse burns and
 * hands the barrel back to its generator, and handles the pickup/steal/toss
 * transitions against the player's carry state. */
#pragma scheduling off
#pragma peephole off
void gunpowderbarrel_update(int obj)
{
    int st = *(int *)(obj + 0xb8);
    u8 *player = Obj_GetPlayerObject();
    int def = *(int *)(obj + 0x4c);

    if (*(f32 *)(st + 0x54) <= lbl_803E4334) {
        *(f32 *)(st + 0x54) += timeDelta;
    }
    if (fn_80080150((void *)(st + 0x18)) != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
        if (timerCountDown((void *)(st + 0x18)) != 0) {
            *(u8 *)(st + 0x17) = 0;
            *(u8 *)(st + 0x16) = 0;
            *(u8 *)(st + 0x49) |= 1;
            *(s16 *)(obj + 6) &= ~0x4000;
            ObjHits_ClearHitVolumes(obj);
            ObjHitbox_SetCapsuleBounds(obj, 8, -2, 0x19);
            ObjHits_EnableObject(obj);
            ObjHits_SyncObjectPositionIfDirty(obj);
            gunpowderbarrel_updatePhysics(obj);
            gunpowderbarrel_setPlayerHeldState(obj, 0);
        }
        return;
    }
    if (fn_80080150((void *)(st + 0x1c)) != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
        timerCountDown((void *)(st + 0x1c));
        memset((void *)(st + 0x20), 0, 0xc);
        memset((void *)(obj + 0x24), 0, 0xc);
        return;
    }
    if (((BarrelBits *)(st + 0x4a))->b5 == 0) {
        if (((BarrelBits *)(st + 0x4a))->b1 != 0 && playerIsDisguised(player) == 0) {
            *(u8 *)(obj + 0xaf) |= 0x10;
        } else {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        }
    }
    if (*(void **)(obj + 0xc8) == NULL) {
        f32 range = lbl_803E4338;
        if ((u32)(*(int *)(st + 0x10) = ObjGroup_FindNearestObject(0x4c, obj, &range)) != 0 &&
            timer_isEffectMode(*(int *)(st + 0x10)) != 0 &&
            *(void **)(*(int *)(st + 0x10) + 0xc4) == NULL) {
            ObjLink_AttachChild(obj, *(int *)(st + 0x10), 0);
        }
    } else {
        if (Obj_IsObjectAlive(*(int *)(st + 0x10)) == 0 && *(void **)(st + 0x10) != NULL) {
            ObjLink_DetachChild(obj, *(int *)(st + 0x10));
            *(int *)(st + 0x10) = 0;
        }
    }
    {
        u32 arg;
        int msg;
        msg = 0;
        arg = 0;
        while (ObjMsg_Pop(obj, &msg, 0, &arg) != 0) {
            switch (msg) {
            case 0xf:
                gunpowderbarrel_setPlayerHeldState(obj, 1);
                break;
            case 0x10:
                gunpowderbarrel_setPlayerHeldState(obj, 0);
                if (arg != 0) {
                    ObjGroup_AddObject(obj, 0x16);
                }
                break;
            }
        }
    }
    if (((BarrelBits *)(st + 0x4a))->b5 != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
    } else {
        *(u8 *)(obj + 0xaf) &= ~8;
    }
    if (*(u8 *)(st + 0x17) != 0) {
        *(u8 *)(st + 0x17) += framesThisStep;
        *(f32 *)(st + 0x2c) =
            *(f32 *)(st + 0x34) * (f32)(u32)*(u8 *)(st + 0x17) + lbl_803E42DC;
        ObjHitbox_SetCapsuleBounds(obj, (s32)*(f32 *)(st + 0x2c),
                                   (s32)(-*(f32 *)(st + 0x2c) * lbl_803E4328),
                                   (s32)(*(f32 *)(st + 0x2c) * lbl_803E4328));
        if (*(void **)(st + 0x10) != NULL) {
            timer_clearManualFlags(*(int *)(st + 0x10));
        }
        if (*(u8 *)(st + 0x17) > 0x14) {
            int i;
            u32 gen;
            if (((BarrelBits *)(st + 0x4a))->b7 != 0) {
                gunpowderbarrel_setPlayerHeldState(obj, 0);
            }
            gen = 0;
            if (*(s16 *)(def + 0x1a) != 0) {
                int cnt;
                int *objs = ObjGroup_GetObjects(0x3a, &cnt);
                int *p;
                i = 0;
                p = objs;
                for (; i < cnt; i++) {
                    if (*(s16 *)(def + 0x1a) == barrelgener_getLinkId(*p)) {
                        gen = objs[i];
                        break;
                    }
                    p++;
                }
            } else {
                gen = ObjGroup_FindNearestObject(0x3a, obj, 0);
            }
            if (gen == 0) {
                objRemoveFromListFn_8002ce88(obj);
                ObjHits_DisableObject(obj);
                *(s16 *)(obj + 6) |= 0x4000;
                s16toFloat((void *)(st + 0x18), 0x3c);
                return;
            }
            memset((void *)(st + 0x20), 0, 0xc);
            memset((void *)(obj + 0x24), 0, 0xc);
            *(u8 *)(st + 0x49) &= ~2;
            ObjHits_RefreshObjectState(obj);
            if (((BarrelBits *)(st + 0x48))->b7 != 0) {
                s16toFloat((void *)(st + 0x18), 0x3c);
                storeZeroToFloatParam((void *)(st + 0x1c));
                s16toFloat((void *)(st + 0x1c), 0x5a);
                barrelgener_queueObjectRelease(gen, obj, 0x46);
                ObjHits_ClearHitVolumes(obj);
                ObjHits_DisableObject(obj);
                *(s16 *)(obj + 6) |= 0x4000;
                return;
            }
            objRemoveFromListFn_8002ce88(obj);
            ObjHits_DisableObject(obj);
            *(s16 *)(obj + 6) |= 0x4000;
            return;
        }
        return;
    }
    if (*(u8 *)(st + 0x15) != 0) {
        if ((playerGetStateFlag310(player) & 0x4000) != 0) {
            setAButtonIcon(5);
        } else {
            setAButtonIcon(4);
        }
    } else {
        if (((BarrelBits *)(st + 0x48))->b6 != 0 && ((BarrelBits *)(st + 0x4a))->b4 != 0 &&
            (*(u8 *)(st + 0x49) & 2) == 0) {
            saveGame_saveObjectPos(obj);
        }
    }
    if ((*(u8 *)(st + 0x49) & 2) != 0 || ((BarrelBits *)(st + 0x4a))->b5 != 0 ||
        (*(int (**)(int, int))((char *)*lbl_803DCAC0 + 0x8))(obj, st) == 0 ||
        (((BarrelBits *)(st + 0x4a))->b1 != 0 && playerIsDisguised(player) == 0)) {
        ObjHits_EnableObject(obj);
        fn_801A1230(obj);
        *(u8 *)(obj + 0x36) = 0xff;
        if (*(u8 *)(st + 0x15) != 0) {
            *(u8 *)(st + 0x15) = 0;
            if (fn_802966B4(player) != 0) {
                ObjHits_SyncObjectPositionIfDirty(obj);
            } else if (fn_8029669C(player) != 0) {
                ObjHits_MarkObjectPositionDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 1);
            } else if (lbl_803E42C0 == fn_80296214(player)) {
                ObjHits_SyncObjectPositionIfDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 0);
            } else if (*(u8 *)(st + 0x17) == 0) {
                *(f32 *)(obj + 0x24) = *(f32 *)(st + 0x20) =
                    fn_80293E80(lbl_803E433C * (f32)*(s16 *)player / lbl_803E4340);
                *(f32 *)(obj + 0x28) = *(f32 *)(st + 0x24) = lbl_803E42C0;
                *(f32 *)(obj + 0x2c) = *(f32 *)(st + 0x28) =
                    sin(lbl_803E433C * (f32)*(s16 *)player / lbl_803E4340);
                *(f32 *)(obj + 0xc) =
                    lbl_803DBE80 * -fn_80293E80(lbl_803E433C * (f32)*(s16 *)player /
                                                lbl_803E4340) +
                    *(f32 *)(obj + 0xc);
                *(f32 *)(obj + 0x14) =
                    lbl_803DBE80 * -sin(lbl_803E433C * (f32)*(s16 *)player / lbl_803E4340) +
                    *(f32 *)(obj + 0x14);
                ObjGroup_AddObject(obj, 0x16);
            }
            ObjGroup_AddObject(obj, 0x16);
        }
        gunpowderbarrel_updatePhysics(obj);
    } else {
        *(u8 *)(st + 0x49) |= 1;
        if (*(u8 *)(st + 0x15) == 0) {
            if (*(void **)(st + 0x10) != NULL) {
                timer_forceStart(*(int *)(st + 0x10));
            }
            ObjGroup_RemoveObject(obj, 0x16);
        }
        *(u8 *)(st + 0x15) = 1;
        ((BarrelBits *)(st + 0x4a))->b6 = 1;
        *(s16 *)(st + 0x50) = *(s16 *)player;
        fn_801A1230(obj);
    }
    if (((BarrelBits *)(st + 0x4a))->b5 != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
        if (((BarrelBits *)(st + 0x4a))->b6 != 0 && ((BarrelBits *)(st + 0x4a))->b7 != 0) {
            *(f32 *)(st + 0x20) = *(f32 *)(obj + 0x24);
            *(f32 *)(st + 0x24) = *(f32 *)(obj + 0x28);
            *(f32 *)(st + 0x28) = *(f32 *)(obj + 0x2c);
            *(f32 *)(st + 0x24) = lbl_803E42C0;
            ((BarrelBits *)(st + 0x4a))->b6 = 0;
        }
    }
    if (*(void **)(st + 0x10) != NULL) {
        if (timer_hasExpired(*(int *)(st + 0x10)) != 0) {
            *(u8 *)(st + 0x16) = 0xa;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
