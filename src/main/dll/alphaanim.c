#include "ghidra_import.h"
#include "main/dll/alphaanim.h"

extern undefined4 FUN_80006ba8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800723a0();

extern undefined4* DAT_803dd6d4;

/*
 * --INFO--
 *
 * Function: doorlock_init
 * EN v1.0 Address: 0x8017C178
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x8017C250
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 doorlock_init(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_3 + 0x80) != '\0') {
    if (((*(byte *)(iVar1 + 0x1b) & 4) != 0) && (*(char *)(param_3 + 0x80) == '\x01')) {
      FUN_80017698((int)*(short *)(iVar1 + 0x1c),1);
    }
    if ((*(char *)(param_3 + 0x80) == '\x02') && (*(short *)(iVar1 + 0x24) != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x58))(param_3);
    }
    *(undefined *)(param_3 + 0x80) = 0;
  }
  *(undefined4 *)(param_1 + 0xf8) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c230
 * EN v1.0 Address: 0x8017C230
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017C30C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c230(int param_1)
{
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c254
 * EN v1.0 Address: 0x8017C254
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8017C330
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c254(int param_1)
{
  char in_r8;
  
  if ((in_r8 == '\0') || (*(int *)(param_1 + 0xf8) != 0)) {
    if (*(int *)(param_1 + 0xf8) != 0) {
      FUN_800400b0();
    }
  }
  else {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c29c
 * EN v1.0 Address: 0x8017C29C
 * EN v1.0 Size: 804b
 * EN v1.1 Address: 0x8017C380
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c29c(int param_1)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  
  pcVar5 = *(char **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (((*(byte *)(param_1 + 0xaf) & 4) == 0) || (uVar2 = FUN_80017690(0x930), uVar2 != 0)) {
    uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x1c));
    *pcVar5 = (char)uVar2;
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      if ((*(ushort *)(iVar4 + 0x26) & 1) != 0) {
        if (*pcVar5 == '\0') {
          *(undefined4 *)(param_1 + 0xf8) = 1;
        }
        else {
          *(undefined4 *)(param_1 + 0xf8) = 0;
        }
      }
    }
    else if (*pcVar5 != '\0') {
      *(undefined *)(param_1 + 0x36) = 0;
    }
    if (*pcVar5 == '\0') {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      if ((((int)*(short *)(iVar4 + 0x22) != 0xffffffff) &&
          (uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x22)), uVar2 == 0)) &&
         (*(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10,
         (*(byte *)(iVar4 + 0x1b) & 0x10) != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
      if (((int)*(short *)(iVar4 + 0x1e) != 0xffffffff) &&
         (uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x1e)), uVar2 == 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      if (((*(short *)(iVar4 + 0x1e) != -1) &&
          (iVar3 = ObjTrigger_IsSetById(param_1,*(short *)(iVar4 + 0x1e)), iVar3 != 0)) ||
         ((*(short *)(iVar4 + 0x1e) == -1 && (iVar3 = ObjTrigger_IsSet(param_1), iVar3 != 0)))) {
        if (*(char *)(iVar4 + 0x20) != -1) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar4 + 0x20),param_1,0xffffffff);
        }
        if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
          FUN_80017698((int)*(short *)(iVar4 + 0x1c),1);
        }
        if ((*(byte *)(iVar4 + 0x1b) & 8) == 0) {
          *pcVar5 = '\x01';
          *(undefined4 *)(param_1 + 0xf4) = 1;
        }
        else {
          FUN_80017698((int)*(short *)(iVar4 + 0x22),0);
        }
        FUN_80006ba8(0,0x100);
      }
    }
    else {
      if (*(int *)(param_1 + 0xf4) == 0) {
        if ((*(char *)(iVar4 + 0x20) != -1) && (*(short *)(iVar4 + 0x24) != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x54))(param_1);
          uVar2 = 1;
          bVar1 = *(byte *)(iVar4 + 0x1b);
          if ((bVar1 & 0x20) != 0) {
            uVar2 = 3;
          }
          if ((bVar1 & 0x40) != 0) {
            uVar2 = uVar2 | 4;
          }
          if ((bVar1 & 0x80) != 0) {
            uVar2 = uVar2 | 8;
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar4 + 0x20),param_1,uVar2);
        }
        *(undefined4 *)(param_1 + 0xf4) = 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0))
    {
      FUN_800400b0();
    }
  }
  else {
    FUN_80006ba8(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x84))(param_1,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    FUN_80017698(0x930,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c5c0
 * EN v1.0 Address: 0x8017C5C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017C6D0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c5c0(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017c5c4
 * EN v1.0 Address: 0x8017C5C4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8017C7EC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017c5c4(int param_1)
{
  if (param_1 != 0) {
    (**(code **)(**(int **)(param_1 + 0x68) + 4))(param_1,*(undefined4 *)(param_1 + 0x4c),0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017c608
 * EN v1.0 Address: 0x8017C608
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x8017C82C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8017c608(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,int param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  
  if (*(short *)(param_9 + 0xb4) != -1) {
    iVar5 = *(int *)(param_9 + 0x4c);
    pbVar4 = *(byte **)(param_9 + 0xb8);
    *(undefined *)(param_11 + 0x56) = 0;
    iVar2 = param_11;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
      bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
      if (bVar1 == 2) {
        if (*(byte *)(iVar5 + 0x24) != 0) {
          param_1 = FUN_80053c98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 (uint)*(byte *)(iVar5 + 0x24),'\0',iVar2,param_12,param_13,param_14
                                 ,param_15,param_16);
        }
      }
      else if (bVar1 < 2) {
        if (((bVar1 != 0) && ((*(byte *)(iVar5 + 0x1d) & 1) == 0)) &&
           ((*(byte *)(iVar5 + 0x1d) & 2) != 0)) {
          param_1 = FUN_80017698((int)*(short *)(iVar5 + 0x18),1);
        }
      }
      else if (bVar1 < 4) {
        iVar2 = 0;
        param_12 = 0;
        param_13 = *DAT_803dd6d4;
        param_1 = (**(code **)(param_13 + 0x50))(0x56,1);
      }
    }
    *pbVar4 = *pbVar4 | 4;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: seqObject_free
 * EN v1.0 Address: 0x8017C7D0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017C960
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_free(int param_1)
{
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: seqObject_render
 * EN v1.0 Address: 0x8017C7F4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017C984
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_render(int param_1)
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
 * Function: seqObject_update
 * EN v1.0 Address: 0x8017C81C
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017C9B4
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_update(int param_1)
{
  uint uVar1;
  byte bVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((*pbVar4 & 4) != 0) {
    bVar2 = *(byte *)(iVar3 + 0x1d);
    if ((bVar2 & 1) == 0) {
      if ((bVar2 & 8) != 0) {
        FUN_80017698((int)*(short *)(iVar3 + 0x18),1);
      }
      *pbVar4 = *pbVar4 | 1;
    }
    else if ((bVar2 & 4) == 0) {
      FUN_80017698((int)*(short *)(iVar3 + 0x1a),0);
    }
    *pbVar4 = *pbVar4 & 0xfb;
  }
  if ((*pbVar4 & 1) == 0) {
    uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x18));
    if (uVar1 != 0) {
      *pbVar4 = *pbVar4 | 1;
    }
    uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x1a));
    bVar2 = (byte)uVar1;
    if ((bVar2 != pbVar4[1]) && (pbVar4[1] = bVar2, bVar2 != 0)) {
      if (*(char *)(iVar3 + 0x1e) != -1) {
        (**(code **)(*DAT_803dd6d4 + 0x84))(param_1,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x1e),param_1,0xffffffff);
      }
      if (((*(byte *)(iVar3 + 0x1d) & 1) == 0) && ((*(byte *)(iVar3 + 0x1d) & 10) == 0)) {
        FUN_80017698((int)*(short *)(iVar3 + 0x18),1);
      }
    }
  }
  else if ((*pbVar4 & 2) == 0) {
    if (((*(byte *)(iVar3 + 0x1d) & 1) != 0) &&
       (uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x18)), uVar1 == 0)) {
      *pbVar4 = *pbVar4 & 0xfe;
    }
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar3 + 0x20));
    if ((*(byte *)(iVar3 + 0x1d) & 0x10) == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x1e),param_1,1);
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x48))
                ((int)*(char *)(iVar3 + 0x1e),param_1,*(undefined2 *)(iVar3 + 0x22));
    }
    *pbVar4 = *pbVar4 & 0xfd;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: seqObject_init
 * EN v1.0 Address: 0x8017CA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017CC04
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObject_init(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017ca44
 * EN v1.0 Address: 0x8017CA44
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x8017CCFC
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017ca44(int param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pbVar3 = *(byte **)(param_1 + 0xb8);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    cVar1 = *(char *)(param_3 + iVar2 + 0x81);
    if (cVar1 == '\x01') {
      FUN_80017698((int)*(short *)(iVar4 + 0x18),1);
      FUN_800723a0();
    }
    else if (cVar1 == '\0') {
      FUN_80017698((int)*(short *)(iVar4 + 0x1a),0);
      FUN_800723a0();
    }
  }
  *pbVar3 = *pbVar3 | 2;
  return 0;
}

/*
 * --INFO--
 *
 * Function: seqObj2_free
 * EN v1.0 Address: 0x8017CAF4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017CDE4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObj2_free(int param_1)
{
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: seqObj2_update
 * EN v1.0 Address: 0x8017CB18
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8017CE10
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObj2_update(int param_1)
{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((*pbVar3 & 1) == 0) {
    if ((*pbVar3 & 2) == 0) {
      if ((((int)*(short *)(iVar2 + 0x1a) == 0xffffffff) ||
          (uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x1a)), uVar1 != 0)) &&
         (((int)*(short *)(iVar2 + 0x18) == 0xffffffff ||
          (uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x18)), uVar1 == 0)))) {
        if ((*(byte *)(iVar2 + 0x1d) & 4) != 0) {
          FUN_80017698((int)*(short *)(iVar2 + 0x1a),0);
          FUN_800723a0();
        }
        if ((*(byte *)(iVar2 + 0x1d) & 0x20) != 0) {
          FUN_80017698((int)*(short *)(iVar2 + 0x18),1);
          FUN_800723a0();
        }
        FUN_800723a0();
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,0xffffffff);
      }
    }
    else {
      if ((*(byte *)(iVar2 + 0x1d) & 2) != 0) {
        FUN_80017698((int)*(short *)(iVar2 + 0x1a),0);
        FUN_800723a0();
      }
      if ((*(byte *)(iVar2 + 0x1d) & 0x10) != 0) {
        FUN_80017698((int)*(short *)(iVar2 + 0x18),1);
        FUN_800723a0();
      }
      *pbVar3 = *pbVar3 & 0xfd;
    }
  }
  else {
    if ((*(byte *)(iVar2 + 0x1d) & 1) != 0) {
      FUN_80017698((int)*(short *)(iVar2 + 0x1a),0);
      FUN_800723a0();
    }
    if ((*(byte *)(iVar2 + 0x1d) & 8) != 0) {
      FUN_80017698((int)*(short *)(iVar2 + 0x18),1);
      FUN_800723a0();
    }
    FUN_800723a0();
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar2 + 0x20));
    (**(code **)(*DAT_803dd6d4 + 0x48))
              ((int)*(char *)(iVar2 + 0x1e),param_1,*(undefined2 *)(iVar2 + 0x22));
    *pbVar3 = *pbVar3 & 0xfe;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: seqObj2_init
 * EN v1.0 Address: 0x8017CCE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D064
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void seqObj2_init(short *param_1,int param_2)
{
}


/* Trivial 4b 0-arg blr leaves. */
void seqobj2_render(void) {}
void seqobj2_hitDetect(void) {}
void fn_8017CBD4(void) {}
void fn_8017CBD8(void) {}
void immultiseq_hitDetect(void) {}
void immultiseq_release(void) {}
void immultiseq_initialise(void) {}
void fn_8017D0D0(void) {}

/* 8b "li r3, N; blr" returners. */
int seqobject_getExtraSize(void) { return 0x3; }
int seqobject_func08(void) { return 0x0; }
int seqobj2_getExtraSize(void) { return 0x1; }
int seqobj2_func08(void) { return 0x0; }
int immultiseq_getExtraSize(void) { return 0x2; }
int immultiseq_func08(void) { return 0x0; }
int fn_8017D06C(void) { return 0x2; }
int fn_8017D074(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E37A0;
extern void fn_8003B8F4(f32);
extern f32 lbl_803E37A8;
extern f32 lbl_803E37B0;
#pragma peephole off
void seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E37A0); }
void immultiseq_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E37A8); }
void fn_8017D0A0(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E37B0); }
#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
int seqobject_free(int x) { return ObjGroup_RemoveObject(x, 0xf); }
int seqobj2_free(int x) { return ObjGroup_RemoveObject(x, 0xf); }
int immultiseq_free(int x) { return ObjGroup_RemoveObject(x, 0xf); }
void fn_8017D07C(int x) { ObjGroup_RemoveObject(x, 0xf); }
#pragma scheduling reset
